"""Detector: interest accrual not updated before a state change (Compound-fork class).

A lending market must accrue interest (update borrowIndex/totalBorrows/exchangeRate)
BEFORE any function that reads or writes that indexed state. If one mutator accrues but
a SIBLING mutator touches the indexed state without accruing first, it prices at a stale
index — mispricing borrows/redemptions.

Low-FP asymmetry gate: only fire on a mutator that writes indexed state and does NOT reach
the accrual function, WHILE another mutator in the same contract DOES — mirrors the
checked/unchecked asymmetry that keeps solvency_check FP-free. No economic simulation.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_ACCRUAL_NAME_RE = re.compile(r"^(accrue\w*|_accrue\w*|_update|updateIndex|_updateIndex|touch)$", re.I)
_INDEXED_STATE_RE = re.compile(r"borrowIndex|totalBorrows?|exchangeRate|interestIndex|supplyIndex|accrualTimestamp", re.I)
_INDEXED_WRITE_RE = re.compile(
    r"(borrowIndex|totalBorrows?|exchangeRate|interestIndex|supplyIndex)\b[^;\n]*=",
    re.I,
)
_MUTATOR_NAME_RE = re.compile(r"^(borrow|repay|redeem|mint|liquidat\w*|withdraw|deposit|supply|seize)\w*$", re.I)


class InterestAccrualAsymmetryDetector(Detector):
    name = "interest_accrual_asymmetry"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _INDEXED_STATE_RE.search(source):
                continue
            fns = [(f, t, strip_comments(b)) for f, _p, t, b in iter_function_bodies(source)]
            accrual = {f for f, _t, b in fns if _ACCRUAL_NAME_RE.match(f) and _INDEXED_STATE_RE.search(b)}
            if not accrual:
                continue

            def reaches_accrual(body: str, tail: str) -> bool:
                return any(
                    re.search(r"\b" + re.escape(a) + r"\s*\(", body) or re.search(r"\b" + re.escape(a) + r"\b", tail)
                    for a in accrual
                )

            mutators = [
                (f, t, b, reaches_accrual(b, t))
                for f, t, b in fns
                if f not in accrual and _MUTATOR_NAME_RE.match(f) and _INDEXED_WRITE_RE.search(b)
            ]
            callers = [m for m in mutators if m[3]]
            omitters = [m for m in mutators if not m[3]]
            if not (callers and omitters):
                continue
            for fname, _t, _b, _ in omitters:
                out.append(FindingCandidate(
                    detector="interest_accrual_asymmetry",
                    title=f"State-mutator touches indexed state without accruing interest: {fname}",
                    description=(
                        f"`{fname}` writes interest-indexed state (borrowIndex/totalBorrows/exchangeRate) but "
                        f"never calls the accrual function ({', '.join(sorted(accrual))}), while sibling "
                        f"mutators ({', '.join(m[0] for m in callers)}) do accrue first. `{fname}` therefore "
                        "prices at a stale index, mispricing the operation (Compound-fork stale-accrual bug). "
                        "Call accrueInterest() at the top of this function too."
                    ),
                    impact_score=7.0,
                    confidence_score=4.5,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={
                        "function": fname, "file": path, "accrual_fns": sorted(accrual),
                        "accruing_siblings": [m[0] for m in callers],
                        "bug_class": "interest_accrual_asymmetry", "needs_poc": True,
                    },
                    next_tests=[
                        f"Call `{fname}` after a gap and check whether it used a stale index vs an accruing sibling",
                        "Confirm no accrual runs (directly or via modifier) before the indexed write",
                    ],
                    affected_functions=[fname],
                ))
        return out
