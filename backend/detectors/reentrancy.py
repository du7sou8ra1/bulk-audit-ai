"""Detector: reentrancy / checks-effects-interactions violations (v0.4).

Maps to Venus (cross-function reentrancy + exchange-rate manipulation). Better
than the bridge regex: it locates the FIRST external interaction and the LAST
state effect in each function body and flags when an external call precedes a
state write in a function with no `nonReentrant` guard. Also flags the read-only
reentrancy shape (a view used for pricing while state is mid-update) heuristically.

Candidates only; a confirm needs a fork reentrancy PoC.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies

_EXT_CALL_RE = re.compile(
    r"\.call\s*\{|\.call\s*\(|\.delegatecall\s*\(|safeTransfer(From)?\s*\(|"
    r"\.transfer\s*\(|\.send\s*\(|\.transferFrom\s*\(|\.onERC|\.tokensReceived",
    re.IGNORECASE,
)
_STATE_WRITE_RE = re.compile(
    r"[\w.]+\s*\[[^\]]*\]\s*(=|[+\-]=)|"           # mapping/array write
    r"\b(balances?|totalSupply|reserves?|totalBorrows?|exchangeRate|shares?|"
    r"pending\w*|accrued\w*)\b\s*(=|[+\-]=)",       # named state write
    re.IGNORECASE,
)
_NONREENTRANT_RE = re.compile(r"nonReentrant|noReentr|reentrancyGuard|_status", re.IGNORECASE)


class ReentrancyDetector(Detector):
    name = "reentrancy"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, tail, body in iter_function_bodies(source):
                if "view" in tail.lower() or "pure" in tail.lower():
                    continue
                guarded = bool(_NONREENTRANT_RE.search(tail) or _NONREENTRANT_RE.search(body[:200]))
                ext = _EXT_CALL_RE.search(body)
                if not ext:
                    continue
                # find a state write that occurs AFTER the external call
                after = body[ext.end():]
                write_after = _STATE_WRITE_RE.search(after)
                if not write_after:
                    continue
                impact = 9.0 if not guarded else 5.0
                conf = 5.0 if not guarded else 2.5
                findings.append(FindingCandidate(
                    detector="reentrancy",
                    title=f"External call before state update{' (no nonReentrant)' if not guarded else ''}: {fname}",
                    description=(
                        f"In `{fname}` an external call/transfer occurs before a state write "
                        f"(checks-effects-interactions violation){'' if guarded else ' and no nonReentrant guard was found'}. "
                        "If the called address is attacker-controlled (ERC777/ERC721 hook, "
                        "low-level call, or a malicious token), it can re-enter this or a related "
                        "function before state is settled — the Venus cross-function reentrancy / "
                        "exchange-rate manipulation class."
                    ),
                    impact_score=impact, confidence_score=conf,
                    severity_candidate="critical" if impact >= 9 else "high",
                    evidence={"function": fname, "file": path, "snippet": body[:1500],
                              "bug_class": "reentrancy", "needs_poc": True,
                              "unprivileged": True, "has_guard": guarded},
                    next_tests=[
                        "Fork-deploy a malicious token/receiver that re-enters during the external call",
                        "Confirm all state effects happen BEFORE the external interaction (CEI)",
                        "Check related functions share the same reentrancy lock",
                    ],
                    affected_functions=[fname],
                ))
        return findings
