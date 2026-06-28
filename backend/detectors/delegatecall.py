"""Detector: delegatecall into an attacker-settable implementation (Furucombo class).

A `delegatecall` runs the target's code in THIS contract's storage/context. If the
target address is attacker-influenced (a function parameter, a mapping element keyed
by caller data, or a body local assigned from calldata/abi.decode) and the function
is not access-controlled, the attacker runs arbitrary code as the contract — drains
approvals, overwrites owner, etc. (Furucombo $14M, Multichain/AnySwap, dForce).

Confirmable when the target is attacker-influenced and unguarded; downgraded to a
lead when an admin guard gates it.
"""
from __future__ import annotations

import re

from .access_control import _INLINE_AUTH_RE  # shared inline body-guard recognizer
from .base import (
    Detector,
    FindingCandidate,
    TargetContext,
    header_has_access_control,
    iter_function_bodies,
    strip_comments,
)
from ..core.semantic_index import ContractFacts, FunctionFacts, build_semantic_index

_HL_DELEGATECALL = re.compile(r"([A-Za-z_][\w.\[\]]*)\s*\.\s*delegatecall\s*[({]")
_ASM_DELEGATECALL = re.compile(r"\bdelegatecall\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,")
_DECODE_ASSIGN = re.compile(r"=\s*[^;]*(abi\.decode|calldata|msg\.data)", re.IGNORECASE)
_TYPE_WORDS = frozenset((
    "address", "uint", "uint256", "bool", "bytes", "bytes32", "string", "this",
    "memory", "calldata", "storage", "payable",
))



_SEMANTIC_GUARD_RE = re.compile(
    r"only[A-Z_]|owner|admin|govern|guardian|keeper|manager|operator|"
    r"hasRole|checkRole|auth|authoriz|controller|allowed|permission|role",
    re.I,
)


def _semantic(ctx: TargetContext) -> ContractFacts | None:
    facts = getattr(ctx, "semantic", None)
    if facts is not None:
        return facts
    try:
        return build_semantic_index(ctx.source_files, ctx.abi)
    except Exception:  # pragma: no cover - detector must fail open, not kill scans
        return None


def _semantic_function(facts: ContractFacts | None, path: str, name: str) -> FunctionFacts | None:
    if facts is None:
        return None
    for fn in facts.functions_by_key.values():
        if fn.file == path and fn.name == name:
            return fn
    return facts.get_function(name)


def _has_semantic_guard(fn: FunctionFacts | None) -> bool:
    if fn is None:
        return False
    text = " ".join(fn.modifiers + fn.guards) + "\n" + fn.tail + "\n" + fn.body
    return bool(header_has_access_control(fn.tail) or _INLINE_AUTH_RE.search(fn.body) or _SEMANTIC_GUARD_RE.search(text))


def _storage_target_guarded_by_admin(facts: ContractFacts | None, base: str) -> bool:
    """True when a storage delegatecall target is only written by guarded code."""
    if facts is None or base not in facts.state_vars:
        return False
    writers = [fn for fn in facts.functions_by_key.values() if base in fn.writes]
    if not writers:
        return False
    for writer in writers:
        if writer.visibility in {"internal", "private"}:
            continue
        if not _has_semantic_guard(writer):
            return False
    return True


def _taint_delegatecall(ctx: TargetContext, fn_name: str) -> dict | None:
    report = getattr(ctx, "taint", None)
    if report is None:
        return None
    for flow in report.flows:
        if flow.sink_kind == "delegatecall" and flow.function == fn_name and flow.confidence >= 0.75:
            return flow.__dict__
    return None

class DelegatecallDetector(Detector):
    name = "delegatecall"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        facts = _semantic(ctx)
        for path, source in ctx.source_files.items():
            if not source:
                continue
            s = strip_comments(source)
            for name, params, tail, body in iter_function_bodies(s):
                if re.search(r"\b(internal|private)\b", tail):
                    continue
                if re.search(r"\b(view|pure)\b", tail):
                    continue
                m = _HL_DELEGATECALL.search(body)
                full = m.group(1) if m else None
                if not m:
                    m = _ASM_DELEGATECALL.search(body)
                    full = m.group(1) if m else None
                if not full:
                    continue
                base = full.split("[")[0].split(".")[0]
                if base.lower() in ("this", "address"):
                    continue

                fn_fact = _semantic_function(facts, path, name)
                pids = [p for p in re.findall(r"[A-Za-z_]\w*", params or "") if p.lower() not in _TYPE_WORDS]
                in_params = any(p == base for p in pids)
                # local assigned from calldata/abi.decode
                from_calldata = bool(
                    re.search(r"\b" + re.escape(base) + r"\s*=\s*[^;]*(abi\.decode|calldata|msg\.data)", body, re.I)
                )
                # subscript target whose key is caller-influenced
                subscript_influenced = False
                ms = re.search(re.escape(base) + r"\s*\[\s*([^\]]+)\]\s*\.\s*delegatecall", body, re.I)
                if ms:
                    key = ms.group(1)
                    subscript_influenced = "msg.sender" in key or any(
                        re.search(r"\b" + re.escape(p) + r"\b", key) for p in pids
                    )
                taint_flow = _taint_delegatecall(ctx, name)
                if not (in_params or from_calldata or subscript_influenced or taint_flow):
                    continue

                storage_admin_set = _storage_target_guarded_by_admin(facts, base)
                if storage_admin_set and not in_params and not from_calldata and subscript_influenced:
                    continue

                guarded = header_has_access_control(tail) or bool(_INLINE_AUTH_RE.search(body)) or _has_semantic_guard(fn_fact)
                impact, conf, tier = (9.0, 8.0, "confirmable") if not guarded else (6.0, 4.0, "lead_only")
                if taint_flow and not guarded:
                    conf = max(conf, 8.5)
                out.append(FindingCandidate(
                    detector="delegatecall",
                    title=f"delegatecall into an attacker-settable target: {name}",
                    description=(
                        f"`{name}` delegatecalls into `{full}`, whose address is "
                        "attacker-influenced (a parameter, a calldata-decoded value, or a "
                        "caller-keyed mapping element)"
                        + ("" if not guarded else " behind an access guard")
                        + ". A delegatecall runs the target's code in this contract's "
                        "storage/context, so an attacker who controls the target executes "
                        "arbitrary code as the contract (overwrite owner, sweep approvals — "
                        "the Furucombo class)."
                    ),
                    impact_score=impact, confidence_score=conf,
                    severity_candidate="critical" if impact >= 9 else "high",
                    evidence={"function": name, "file": path, "snippet": body[:1500],
                              "bug_class": "delegatecall_to_untrusted_implementation",
                              "onchain_detectable": tier, "needs_poc": True,
                              "unprivileged": not guarded, "target": full,
                              "semantic_facts": bool(fn_fact),
                              "storage_target_admin_set": storage_admin_set,
                              "taint_flow": taint_flow,
                              "user_controlled_target_or_data": bool(in_params or from_calldata or subscript_influenced or taint_flow)},
                    next_tests=[
                        "Deploy a malicious implementation at the caller-supplied target; delegatecall it and overwrite owner/approvals.",
                        "Confirm the target is not constrained to an immutable/whitelisted implementation.",
                    ],
                    affected_functions=[name],
                ))
        return out
