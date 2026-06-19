"""Detector: time / unlock-logic flaws (v0.4).

Maps to DxSale (unlock-time backdating -> LP drain). Shapes:

  * a setter that writes an unlock/release/lock timestamp with NO check that the
    new time is >= the old one (or >= now) -> the owner can move an unlock into
    the past and withdraw early.
  * a withdraw/release/unlock gated on `block.timestamp >= unlockTime` where
    `unlockTime` is owner-settable without a monotonicity guard.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies

_TIME_VAR_RE = re.compile(r"(unlock|release|lock|vesting|cliff|maturity|expir)\w*time\w*",
                          re.IGNORECASE)
_SET_RE = re.compile(r"(unlock|release|lock|vesting|cliff|maturity|expir)\w*\s*=", re.IGNORECASE)
_MONOTONIC_RE = re.compile(
    r">=?\s*[\w.]*(unlock|release|lock|maturity|block\.timestamp)|"
    r"require\s*\([^)]*(>=|>)\s*[^)]*(time|timestamp)", re.IGNORECASE
)
_GATE_RE = re.compile(r"block\.timestamp\s*(>=|>)\s*\w*(unlock|release|lock|maturity)\w*", re.IGNORECASE)
_WITHDRAWISH = ("withdraw", "release", "unlock", "claim", "drain", "removeliquidity")


class TimeLogicDetector(Detector):
    name = "time_logic"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        text = ctx.all_source_text()
        if not text or not _TIME_VAR_RE.search(text):
            return []
        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, _tail, body in iter_function_bodies(source):
                lname = fname.lower()
                # setter that writes an unlock time with no monotonicity guard
                if _SET_RE.search(body) and ("set" in lname or "update" in lname or "extend" in lname):
                    if not _MONOTONIC_RE.search(body):
                        findings.append(self._c(
                            fname, path, body, impact=7.5, conf=4.5,
                            title=f"Unlock/lock time set without monotonicity guard: {fname}",
                            desc=(f"`{fname}` assigns an unlock/release/lock timestamp but no check "
                                  "that the new value is >= the previous one (or >= now) was found. "
                                  "A privileged caller could backdate the unlock and withdraw early "
                                  "(DxSale class)."),
                            tests=["Confirm new unlock time must be >= existing unlock time",
                                   "Fork-set the unlock into the past, then attempt an early withdraw"]))
                # withdraw gated on an owner-settable unlock time
                if any(k in lname for k in _WITHDRAWISH) and _GATE_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, impact=6.5, conf=3.5,
                        title=f"Withdraw gated on a mutable unlock timestamp: {fname}",
                        desc=(f"`{fname}` releases funds when block.timestamp passes an unlock time. "
                              "If that timestamp is owner-settable without a monotonic guard, the "
                              "time lock can be bypassed."),
                        tests=["Trace whether the unlock timestamp can be reduced by a privileged call"]))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, tests):
        return FindingCandidate(
            detector="time_logic", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="high" if impact >= 7 else "medium",
            evidence={"function": fname, "file": path, "snippet": body[:1500],
                      "bug_class": "time", "needs_poc": True,
                      # owner-settable -> often governance; refuter/AI will judge scope.
                      "unprivileged": False, "governance_controlled": True},
            next_tests=tests, affected_functions=[fname],
        )
