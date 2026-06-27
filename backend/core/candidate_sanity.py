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


def apply_candidate_sanity(ctx: TargetContext, candidates: list[FindingCandidate]) -> int:
    """Mutate candidates with ``evidence['suppressed']`` for deterministic FPs.

    Returns the number of candidates suppressed by this pass.
    """
    entries = _function_entries(ctx)
    abi_names = _abi_function_names(ctx)
    suppressed = 0
    for cand in candidates:
        if (cand.evidence or {}).get("suppressed"):
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

    if matches and all(_is_internal_only(e.tail) for e in matches):
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


def _suppress(cand: FindingCandidate, reason: str) -> None:
    ev = cand.evidence or {}
    ev["suppressed"] = True
    ev["suppressed_reason"] = reason
    ev["sanity_filter"] = True
    ev["refuted"] = True
    ev["refutation"] = {"attempted": True, "is_real": False, "refutation": reason}
    cand.evidence = ev
