"""Detector: rewardPerToken divides by total supply with no zero-supply guard.

Synthetix-style `rewardPerToken()` / `earned()` divides accumulated rewards by
`totalSupply`/`totalStaked`. If the first staker triggers it while supply is 0 (or after
a full unstake), the division reverts and can brick staking, or mis-accounts. The
existing accumulator detector only matches MasterChef naming; this covers the Synthetix
shape.

Signal: a division by total(Supply|Staked|Shares) inside a reward accumulator/view, with
no `if (total==0) return` / `> 0` / `require(total>0)` guard in the same body.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_REWARD_FN_RE = re.compile(r"rewardPerToken|rewardPerShare|earned|rewardIndex|_updateReward", re.I)
_DIV_SUPPLY_RE = re.compile(r"/\s*(_?total(?:Supply|Staked|Shares|Deposits))\b", re.I)
_ZERO_GUARD_RE = re.compile(
    r"(_?total(?:Supply|Staked|Shares|Deposits))\s*==\s*0|"
    r"(_?total(?:Supply|Staked|Shares|Deposits))\s*(?:>|!=)\s*0|"
    r"require\s*\([^;]*(_?total(?:Supply|Staked|Shares|Deposits))\s*>\s*0",
    re.I,
)


class RewardPerTokenZeroSupplyDetector(Detector):
    name = "reward_per_token_zero_supply"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                body = strip_comments(raw_body)
                # reward context: either a reward-y function name, or a reward accumulator token in the body.
                if not (_REWARD_FN_RE.search(fname) or _REWARD_FN_RE.search(body)):
                    continue
                if not _DIV_SUPPLY_RE.search(body):
                    continue
                if _ZERO_GUARD_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector="reward_per_token_zero_supply",
                    title=f"Reward accumulator divides by total supply with no zero guard: {fname}",
                    description=(
                        f"`{fname}` divides by total(Supply/Staked/Shares) to compute a reward-per-token with no "
                        "`if (total == 0) return` / `require(total > 0)` guard. When supply is zero (first "
                        "staker, or after a full unstake) this reverts — bricking staking/claims or corrupting "
                        "reward accounting. Guard the zero-supply case (Synthetix-style)."
                    ),
                    impact_score=7.0,
                    confidence_score=4.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "bug_class": "reward_per_token_zero_supply", "needs_poc": True},
                    next_tests=[
                        "Call the reward view with zero total supply on a fork; expect a revert / bad value",
                        "Confirm no zero-supply short-circuit guards the division",
                    ],
                    affected_functions=[fname],
                ))
        return out
