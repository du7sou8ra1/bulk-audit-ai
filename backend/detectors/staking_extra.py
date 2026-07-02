"""Detector: emergencyWithdraw leaves stale reward/global accounting (MasterChef forks).

A canonical safe `emergencyWithdraw` forfeits rewards AND keeps accounting consistent:
it zeroes the user's stake, resets `user.rewardDebt`, AND decrements the global
`totalStaked`/`totalSupply`. A fork that zeroes the stake and pays out principal but
forgets to reset rewardDebt or decrement the global lets the user later over-claim
rewards or corrupts everyone's reward share.

Positive-anchored (name gate + `amount=0`/`delete` + transfer present), then fires on
the ABSENCE of the reset/decrement — low FP.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_EMERGENCY_RE = re.compile(r"^(emergency\w*|exit|forceWithdraw|panicWithdraw)$", re.I)
_ZERO_STAKE_RE = re.compile(r"\.amount\s*=\s*0|delete\s+\w+\[|delete\s+user\b|\bamount\s*=\s*0\b", re.I)
_TRANSFER_RE = re.compile(r"\.transfer\s*\(|safeTransfer\s*\(|\.call\s*\{", re.I)
_REWARD_DEBT_RESET_RE = re.compile(r"rewardDebt\s*=", re.I)
_GLOBAL_DECREMENT_RE = re.compile(r"(totalStaked|totalSupply|totalDeposits|totalShares|totalAllocPoint)\s*-=|"
                                  r"(totalStaked|totalSupply|totalDeposits|totalShares)\s*=\s*\w+\s*-", re.I)


class EmergencyWithdrawStaleDebtDetector(Detector):
    name = "emergency_withdraw_stale_debt"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if not _EMERGENCY_RE.match(fname):
                    continue
                body = strip_comments(raw_body)
                if not (_ZERO_STAKE_RE.search(body) and _TRANSFER_RE.search(body)):
                    continue
                missing = []
                if not _REWARD_DEBT_RESET_RE.search(body):
                    missing.append("does not reset user.rewardDebt")
                if not _GLOBAL_DECREMENT_RE.search(body):
                    missing.append("does not decrement the global totalStaked/totalSupply")
                if not missing:
                    continue
                out.append(FindingCandidate(
                    detector="emergency_withdraw_stale_debt",
                    title=f"emergencyWithdraw leaves stale accounting: {fname}",
                    description=(
                        f"`{fname}` zeroes the user's stake and transfers principal but " + " and ".join(missing) +
                        ". A safe emergency exit must also reset rewardDebt and decrement the global stake, or "
                        "the user can later over-claim rewards / everyone's reward-per-share is corrupted "
                        "(MasterChef-fork accounting bug)."
                    ),
                    impact_score=6.5,
                    confidence_score=4.5,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="medium",
                    evidence={
                        "function": fname, "file": path, "bug_class": "emergency_withdraw_stale_debt",
                        "missing": missing, "needs_poc": True,
                    },
                    next_tests=[
                        "Stake, emergencyWithdraw, then claim rewards on a fork; expect an over-claim or revert",
                        "Confirm rewardDebt reset and totalStaked decrement are both absent",
                    ],
                    affected_functions=[fname],
                ))
        return out
