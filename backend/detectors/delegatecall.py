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

_HL_DELEGATECALL = re.compile(r"([A-Za-z_][\w.\[\]]*)\s*\.\s*delegatecall\s*[({]")
_ASM_DELEGATECALL = re.compile(r"\bdelegatecall\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,")
_DECODE_ASSIGN = re.compile(r"=\s*[^;]*(abi\.decode|calldata|msg\.data)", re.IGNORECASE)
_TYPE_WORDS = frozenset((
    "address", "uint", "uint256", "bool", "bytes", "bytes32", "string", "this",
    "memory", "calldata", "storage", "payable",
))


class DelegatecallDetector(Detector):
    name = "delegatecall"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
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
                if not (in_params or from_calldata or subscript_influenced):
                    continue

                guarded = header_has_access_control(tail) or bool(_INLINE_AUTH_RE.search(body))
                impact, conf, tier = (9.0, 8.0, "confirmable") if not guarded else (6.0, 4.0, "lead_only")
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
                              "unprivileged": not guarded, "target": full},
                    next_tests=[
                        "Deploy a malicious implementation at the caller-supplied target; delegatecall it and overwrite owner/approvals.",
                        "Confirm the target is not constrained to an immutable/whitelisted implementation.",
                    ],
                    affected_functions=[name],
                ))
        return out
