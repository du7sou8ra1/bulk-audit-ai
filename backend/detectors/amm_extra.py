"""Detector: CLMM rounding-direction asymmetry (lead-level).

In a concentrated-liquidity AMM, the amount a user is PAID on withdraw/collect/burn
should round DOWN and the amount they DEPOSIT should round UP (both in the protocol's
favor). A fork that rounds a payout UP (`mulDivRoundingUp` / `(x + d - 1)/d`) while the
paired deposit rounds down over-pays users and drains reserves over many cycles.

Gated on CLMM context + a payout fn using the ceil idiom + a deposit/mint sibling using
plain division, so it does not flag payouts that are legitimately ceiled everywhere.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_CLMM_CTX_RE = re.compile(r"sqrtPrice|liquidity|\btick\b|getAmount0|getAmount1|position|nonfungible", re.I)
_CEIL_RE = re.compile(r"mulDivRoundingUp|RoundingUp|Rounding\.Up|Rounding\.Ceil|ceilDiv|\+\s*\w+\s*-\s*1\s*\)\s*/")
_PLAIN_DIV_RE = re.compile(r"[\w.\)\]]\s*\*\s*[\w.\(]+\s*/\s*[\w.\(]")
_PAYOUT_FN_RE = re.compile(r"withdraw|collect|burn|redeem|decreaseLiquidity|removeLiquidity", re.I)
_DEPOSIT_FN_RE = re.compile(r"deposit|^mint|increaseLiquidity|addLiquidity|^_mint", re.I)


class ClmmRoundingAsymmetryDetector(Detector):
    name = "clmm_rounding_asymmetry"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _CLMM_CTX_RE.search(source):
                continue
            fns = [(f, strip_comments(b)) for f, _p, _t, b in iter_function_bodies(source)]
            # A deposit/mint sibling that rounds DOWN (plain mul-div, no ceil) must exist.
            has_rounddown_deposit = any(
                _DEPOSIT_FN_RE.search(f) and _PLAIN_DIV_RE.search(b) and not _CEIL_RE.search(b)
                for f, b in fns
            )
            if not has_rounddown_deposit:
                continue
            for fname, body in fns:
                if not _PAYOUT_FN_RE.search(fname):
                    continue
                if not _CEIL_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector="clmm_rounding_asymmetry",
                    title=f"CLMM payout rounds UP while deposit rounds down: {fname}",
                    description=(
                        f"`{fname}` rounds a user PAYOUT up (mulDivRoundingUp / ceil idiom) while a paired "
                        "deposit/mint path rounds down. Both should round in the protocol's favor (payouts "
                        "down, deposits up); the asymmetry over-pays users a wei per op and drains liquidity "
                        "over many cycles (CLMM-fork solvency). Round the payout down."
                    ),
                    impact_score=7.0,
                    confidence_score=3.5,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "bug_class": "clmm_rounding_asymmetry", "needs_poc": True},
                    next_tests=[
                        "Loop deposit+withdraw many times on a fork; measure whether protocol reserves leak",
                        "Confirm the payout rounds up while the deposit sibling rounds down",
                    ],
                    affected_functions=[fname],
                ))
        return out
