"""Context-aware false-positive gates for detector candidates.

Detectors are intentionally broad. This pass runs before scoring/AI so obvious
wrong-target and normal-user-method matches cannot become critical findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..detectors.base import FindingCandidate, TargetContext, iter_function_bodies


@dataclass(frozen=True)
class FunctionEntry:
    name: str
    params: str
    tail: str
    body: str
    file: str


_STRICT_ABI_DETECTORS = {
    "access_control",
    "proxy_upgrade",
    "delegatecall",
    "unprotected_initializer",
    "reinitializable_proxy_delegatecall",
    "bridge_zero_root_acceptance",
    "verifier_address_spoof",
    "bridge_keeper_mutation",
    "bridge_zero_root",
}
_INIT_NAME_RE = re.compile(r"^(initialize|init|__init|setup|configure|reinitialize|reinit)\w*$", re.I)
_INIT_GUARD_RE = re.compile(
    r"\binitializer\b|\breinitializer\s*\(|\bonlyUninitialized\b|"
    r"require\s*\([^)]*!+\s*_?initialized|require\s*\([^)]*initialized|"
    r"require\s*\([^)]*(owner|admin)\s*==\s*address\s*\(\s*0\s*\)",
    re.I,
)
_AMM_ONE_TIME_INIT_RE = re.compile(
    r"factory\s*==\s*address\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)\s*==\s*factory|"
    r"slot0\s*\.\s*sqrtPriceX96\s*==\s*0|0\s*==\s*slot0\s*\.\s*sqrtPriceX96",
    re.I,
)
_PROXY_ADMIN_GATE_RE = re.compile(
    r"\bproxyCallIfNotAdmin\b|\bifAdmin\b|\bifNotAdmin\b|"
    r"_requireAdmin\s*\(|_checkAdmin\s*\(|_fallback\s*\(",
    re.I,
)
_UPGRADE_NAME_RE = re.compile(r"^(upgradeTo|upgradeToAndCall|upgrade|upgradeAndCall|changeImplementation|setImplementation)$")
_USER_EXIT_NAME_RE = re.compile(r"^(withdraw|redeem)$", re.I)
_USER_MINT_NAME_RE = re.compile(r"^(deposit|mint)$", re.I)
_PRIV_WORD_RE = re.compile(
    r"owner|admin|govern|guardian|operator|keeper|manager|treasury|collector|"
    r"withdrawCollected|collectFees|sweep|rescue|pause|upgrade|implementation",
    re.I,
)
_VERIFY_HELPER_RE = re.compile(r"verify|verifier|proof|validate", re.I)
_VALUE_OR_STATE_RE = re.compile(
    r"=\s*[^=]|delete\b|push\s*\(|_mint\s*\(|_burn\s*\(|"
    r"\.transfer\s*\(|safeTransfer\s*\(|safeTransferFrom\s*\(|transferFrom\s*\(|\.call\s*[({]",
    re.I,
)
_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
_APPROVAL_LIKE_RE = re.compile(r"approval|allowance|transferfrom|drain|router", re.I)
_SOURCE_ROLE_RE = re.compile(r"source|src|from|owner|payer|victim", re.I)
_SAFE_ASSIGNMENTS = (
    ("msg.sender", re.compile(r"\b{var}\b\s*=\s*(?:_msgSender\s*\(\s*\)|msg\.sender)\b", re.I)),
    ("address(this)", re.compile(r"\b{var}\b\s*=\s*address\s*\(\s*this\s*\)", re.I)),
)


def apply_candidate_sanity(
    ctx: TargetContext,
    candidates: list[FindingCandidate],
    *,
    enable_liveness: bool = True,
    enable_binding_gate: bool = True,
) -> int:
    """Mutate candidates with ``evidence['suppressed']`` for deterministic FPs.

    Returns the number of candidates suppressed by this pass.
    """
    entries = _function_entries(ctx)
    abi_names = _abi_function_names(ctx)
    suppressed = 0
    for cand in candidates:
        if (cand.evidence or {}).get("suppressed"):
            continue
        if enable_liveness:
            _attach_liveness_evidence(ctx, cand)
        if enable_binding_gate:
            binding_reason = _binding_refutation_for_candidate(cand, entries)
            if binding_reason:
                _suppress(cand, binding_reason, concrete=True, pattern_class="attacker_binding_safe")
                suppressed += 1
                continue
        reason = _suppression_reason(ctx, cand, entries, abi_names)
        if reason:
            _suppress(cand, reason)
            suppressed += 1
    return suppressed


def _suppression_reason(
    ctx: TargetContext,
    cand: FindingCandidate,
    entries: dict[str, list[FunctionEntry]],
    abi_names: set[str],
) -> str:
    fn = _candidate_function(cand)
    if not fn:
        return ""

    matches = entries.get(fn.lower(), [])
    if ctx.source_files and not matches and fn not in abi_names:
        return f"function `{fn}` is absent from the target source and ABI"

    if (
        matches
        and all(_is_internal_only(e.tail) for e in matches)
        and not _keep_internal_helper_lead(cand)
    ):
        return f"function `{fn}` is internal/private in the verified target source"

    if (
        abi_names
        and cand.detector in _STRICT_ABI_DETECTORS
        and fn not in abi_names
        and not any((e.file or "").replace("\\", "/").startswith("_modules/") for e in matches)
    ):
        return f"function `{fn}` is not exposed by the target or implementation ABI"

    if _UPGRADE_NAME_RE.match(fn) and any(_PROXY_ADMIN_GATE_RE.search(e.tail + "\n" + e.body) for e in matches):
        return f"`{fn}` is behind a proxy admin gate such as proxyCallIfNotAdmin/ifAdmin"

    if _INIT_NAME_RE.match(fn):
        live = _read_initialized(ctx)
        if live is True:
            return f"`{fn}` is not exploitable on this target: live isInitialized()/initialized() is true"
        if matches and any(_AMM_ONE_TIME_INIT_RE.search(e.tail + "\n" + e.body) for e in matches):
            return f"`{fn}` is an AMM pool one-time factory initializer guarded by factory/slot0 state"
        if matches and any(_INIT_GUARD_RE.search(e.tail + "\n" + e.body) for e in matches):
            return f"`{fn}` has a visible one-shot initializer guard"

    if cand.detector == "access_control" and _looks_like_normal_user_asset_method(fn, matches):
        return f"`{fn}` is a normal account-bound vault/token user method, not a privileged admin method"

    if cand.detector in {"access_control", "verifier_address_spoof"} and _looks_like_pure_verifier_helper(fn, matches):
        return f"`{fn}` looks like a helper verifier/validator with no state/value-moving sink"

    return ""


def _function_entries(ctx: TargetContext) -> dict[str, list[FunctionEntry]]:
    out: dict[str, list[FunctionEntry]] = {}
    for path, src in (ctx.source_files or {}).items():
        for name, params, tail, body in iter_function_bodies(src or ""):
            out.setdefault(name.lower(), []).append(FunctionEntry(name, params, tail, body, path))
    return out


def _abi_function_names(ctx: TargetContext) -> set[str]:
    abi = ctx.abi
    if isinstance(abi, dict):
        abi = abi.get("abi")
    if not isinstance(abi, list):
        return set()
    return {
        str(item.get("name"))
        for item in abi
        if isinstance(item, dict) and item.get("type") == "function" and item.get("name")
    }


def _candidate_function(cand: FindingCandidate) -> str:
    ev = cand.evidence or {}
    names = list(cand.affected_functions or [])
    if ev.get("function"):
        names.append(str(ev.get("function")))
    for name in names:
        n = str(name or "").strip()
        if not n or n == "?":
            continue
        return n.split("(")[0]
    m = re.search(r":\s*([A-Za-z_]\w*)\s*$", cand.title or "")
    return m.group(1) if m else ""


def _is_internal_only(tail: str) -> bool:
    return bool(re.search(r"\b(internal|private)\b", tail or ""))


def _keep_internal_helper_lead(cand: FindingCandidate) -> bool:
    """Do not suppress Aztec-style settlement/proof leads on helper visibility.

    The vulnerable variable is often decoded in an internal helper and consumed
    by a public entrypoint. Internal/private only proves users cannot call the
    helper directly; it does not prove the proof-boundary or settlement-count
    invariant is safe. A concrete binding check should refute these later.
    """
    ev = cand.evidence or {}
    if not (ev.get("lead_only") or ev.get("onchain_detectable") == "lead_only"):
        return False
    blob = " ".join(
        str(x or "")
        for x in (
            cand.detector,
            cand.title,
            cand.description,
            ev.get("bug_class"),
            ev.get("pattern"),
            ev.get("source"),
        )
    ).lower()
    return bool(
        cand.detector in {"zk_verifier", "invariant_reasoner"}
        or any(
            marker in blob
            for marker in (
                "proof",
                "settlement",
                "numtx",
                "num_tx",
                "rollup",
                "public input",
                "nullifier",
                "merkle",
                "root",
                "withdraw",
            )
        )
    )


def _read_initialized(ctx: TargetContext) -> bool | None:
    onchain = getattr(ctx, "onchain", None)
    if onchain is None or not getattr(onchain, "available", False):
        return None
    for sig in ("isInitialized()", "initialized()"):
        try:
            val = onchain.call_typed(ctx.address, sig, return_types=["bool"])
        except Exception:
            val = None
        if isinstance(val, bool):
            return val
    return None


def _attach_liveness_evidence(ctx: TargetContext, cand: FindingCandidate) -> None:
    blob = f"{cand.detector} {cand.title} {cand.description} {ctx.contract_name}".lower()
    if not any(k in blob for k in ("init", "initializer", "proxy", "vault")):
        return
    onchain = getattr(ctx, "onchain", None)
    if onchain is None or not getattr(onchain, "available", False):
        return
    checks = []
    zero_seen = False
    for sig in ("owner()", "factory()", "asset()"):
        try:
            val = onchain.call_typed(ctx.address, sig, return_types=["address"])
        except Exception:
            val = None
        if val is None:
            continue
        try:
            zero = int(str(val), 16) == 0
        except Exception:
            zero = False
        checks.append({"getter": sig, "value": _ZERO_ADDRESS if zero else str(val), "zero": zero})
        zero_seen = zero_seen or zero
    if not checks:
        return
    ev = cand.evidence or {}
    ev["liveness_getters"] = checks
    if zero_seen:
        ev["never_initialized"] = True
    cand.evidence = ev


def _claimed_attacker_bindings(ev: dict) -> list[dict]:
    out: list[dict] = []
    for key in ("attacker_control_binding", "attacker_binding"):
        item = ev.get(key)
        if isinstance(item, dict):
            out.append(item)
    vals = ev.get("attacker_controlled_variables") or ev.get("controlled_variables") or []
    if isinstance(vals, str):
        vals = [vals]
    if isinstance(vals, list):
        for val in vals:
            if isinstance(val, dict):
                out.append(val)
            elif val:
                out.append({"variable": str(val)})
    for key in ("attacker_controlled_variable", "attacker_variable", "controlled_variable"):
        if ev.get(key):
            out.append({"variable": str(ev.get(key)), "role": str(ev.get("attacker_variable_role", ""))})
    seen = set()
    unique = []
    for item in out:
        var = str(item.get("variable") or "").strip()
        if not var or var in seen:
            continue
        seen.add(var)
        unique.append(item)
    return unique


def deterministic_attacker_binding_refutation(
    code: str,
    evidence: dict,
    *,
    detector: str = "",
    title: str = "",
) -> str:
    """Hard-gate hallucinated attacker-control bindings using cited code."""
    if not code or not evidence:
        return ""
    blob = f"{detector} {title} {evidence.get('bug_class', '')}"
    approval_like = bool(_APPROVAL_LIKE_RE.search(blob))
    for item in _claimed_attacker_bindings(evidence):
        var = str(item.get("variable") or "").strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", var):
            continue
        role = str(item.get("role") or item.get("kind") or item.get("binding_role") or "").lower()
        var_re = re.escape(var)
        if re.search(rf"\b(?:immutable|constant)\b[^;\n]*\b{var_re}\b|\b{var_re}\b[^;\n]*\b(?:immutable|constant)\b", code, re.I):
            return f"cited attacker-controlled variable `{var}` is immutable/constant in the cited code"
        for label, template in _SAFE_ASSIGNMENTS:
            pat = re.compile(template.pattern.format(var=var_re), template.flags)
            if not pat.search(code):
                continue
            if label == "msg.sender":
                source_like = bool(_SOURCE_ROLE_RE.search(role)) or bool(
                    re.search(rf"(safeTransferFrom|transferFrom)\s*\(\s*{var_re}\s*,", code, re.I)
                )
                if approval_like and source_like:
                    return (
                        f"cited transfer source `{var}` is caller-bound to msg.sender; "
                        "the caller spends their own approval, not a third-party approval"
                    )
                continue
            return f"cited attacker-controlled variable `{var}` is bound to {label} in the cited code"
    return ""


def _binding_refutation_for_candidate(
    cand: FindingCandidate,
    entries: dict[str, list[FunctionEntry]],
) -> str:
    fn = _candidate_function(cand)
    code = ""
    if fn:
        code = "\n".join((e.tail + "\n" + e.body) for e in entries.get(fn.lower(), []))
    if not code:
        code = str((cand.evidence or {}).get("snippet", ""))
    return deterministic_attacker_binding_refutation(
        code,
        cand.evidence or {},
        detector=cand.detector,
        title=cand.title,
    )


def _looks_like_normal_user_asset_method(fn: str, matches: list[FunctionEntry]) -> bool:
    if not (_USER_EXIT_NAME_RE.match(fn) or _USER_MINT_NAME_RE.match(fn)):
        return False
    for e in matches:
        b = e.body or ""
        if _PRIV_WORD_RE.search(b):
            continue
        if _USER_EXIT_NAME_RE.match(fn):
            burns_user_claim = bool(
                re.search(r"_burn\s*\([^;]*(msg\.sender|_msgSender\s*\(|owner)", b, re.I)
                or re.search(r"balances?\s*\[\s*(msg\.sender|_msgSender\s*\(|owner)", b, re.I)
            )
            pays_user = bool(re.search(r"(msg\.sender|_msgSender\s*\(|receiver|to)", b))
            if burns_user_claim and pays_user:
                return True
        if _USER_MINT_NAME_RE.match(fn):
            pulls_assets = bool(re.search(r"(transferFrom|safeTransferFrom)\s*\(", b, re.I))
            mints_user = bool(re.search(r"_mint\s*\([^;]*(msg\.sender|_msgSender\s*\(|receiver|to|owner)", b, re.I))
            if pulls_assets and mints_user:
                return True
    return False


def _looks_like_pure_verifier_helper(fn: str, matches: list[FunctionEntry]) -> bool:
    if not _VERIFY_HELPER_RE.search(fn):
        return False
    return bool(matches) and all(not _VALUE_OR_STATE_RE.search(e.body or "") for e in matches)


def _suppress(
    cand: FindingCandidate,
    reason: str,
    *,
    concrete: bool = False,
    pattern_class: str = "",
) -> None:
    ev = cand.evidence or {}
    ev["suppressed"] = True
    ev["suppressed_reason"] = reason
    ev["sanity_filter"] = True
    ev["refuted"] = True
    if concrete:
        ev["refuted_concrete"] = True
    if pattern_class:
        ev["refutation_pattern_class"] = pattern_class
    ev["refutation"] = {
        "attempted": True,
        "is_real": False,
        "refutation": reason,
        "concrete_mitigation": concrete,
    }
    cand.evidence = ev
