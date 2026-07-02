"""Detectors: DeFi lending accounting gaps (probed uncovered by the live engine).

1. BorrowCapNotEnforcedDetector — a (borrow|supply)Cap / debtCeiling storage var
   exists, but the borrow mutator increments the GLOBAL total with no `require` that
   compares the cap against total+amount. A defined-but-unenforced cap is an Aave-V3
   risk-parameter bypass / bad-debt vector.

2. BadDebtNoSocializationDetector — a liquidation path with an underwater branch
   (`collateral < debt` / `seized < debt`) that zeroes the borrower's debt but performs
   NO deficit sink (no reserve/badDebt/deficit write-down, no global totalBorrows
   decrement), while share redemption still values assets off that debt. Euler /
   isolated-market insolvency (bank-run). Lead-only (socialization is often in a
   separate module), gated on whole-contract absence of deficit/reserve identifiers.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_CAP_DECL_RE = re.compile(r"\b((?:borrow|supply)Cap|debtCeiling|debtCap|supplyCap|borrowCap)\b")
_BORROW_FN_RE = re.compile(r"^(borrow|increaseDebt|_borrow|mintDebt|takeLoan)\w*$", re.I)
_GLOBAL_TOTAL_INC_RE = re.compile(
    r"(totalBorrows?|totalDebt|totalSupplied|totalBorrowed|totalPrincipal)\b[^;\n]*\+=|"
    r"(totalBorrows?|totalDebt|totalSupplied)\b\s*=\s*[^;]*\+",
    re.I,
)

_LIQ_FN_RE = re.compile(r"liquidat|seize|closePosition|repayBadDebt|absorb", re.I)
_UNDERWATER_RE = re.compile(
    r"(collateral|coll|seized|seizeAmount)\s*<\s*(debt|owed|borrow|repay)|"
    r"(debt|owed|borrow)\s*>\s*(collateral|coll|seized)",
    re.I,
)
_DEBT_ZERO_RE = re.compile(
    r"(?:debt|borrows?|owed|principal)\w*(?:\s*\[[^\]]*\])?\s*=\s*0\b|"
    r"delete\s+\w*[Dd]ebt|delete\s+\w*[Bb]orrow",
    re.I,
)
_DEFICIT_SINK_RE = re.compile(r"deficit|badDebt|reserve|writeDown|writeOff|socializ|shortfall", re.I)

_HEALTH_FN_RE = re.compile(r"health|solvenc|isLiquidatable|checkCollateral|accountLiquidity|isHealthy", re.I)
_COLLATERAL_RE = re.compile(r"\bcollateral\b|\bcoll\b|collateralValue", re.I)
_DEBT_TERM_RE = re.compile(r"\bdebt\b|\bborrow\w*\b|\bowed\b|required", re.I)
_CEIL_IDIOM_RE = re.compile(r"mulDivRoundingUp|RoundingUp|Rounding\.Up|Rounding\.Ceil|ceilDiv|\+\s*\w+\s*-\s*1\s*\)\s*/")
_GTE_RE = re.compile(r">=")


class BorrowCapNotEnforcedDetector(Detector):
    name = "borrow_cap_not_enforced"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            caps = {m.group(1) for m in _CAP_DECL_RE.finditer(source)}
            if not caps:
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if not _BORROW_FN_RE.match(fname):
                    continue
                body = strip_comments(raw_body)
                if not _GLOBAL_TOTAL_INC_RE.search(body):
                    continue
                # The cap must be compared in this borrow path.
                if any(re.search(r"\b" + re.escape(c) + r"\b", body) for c in caps):
                    continue
                out.append(FindingCandidate(
                    detector="borrow_cap_not_enforced",
                    title=f"Borrow/supply cap defined but not enforced in the borrow path: {fname}",
                    description=(
                        f"The contract declares a cap ({', '.join(sorted(caps))}) but `{fname}` increments the "
                        "global borrow/supply total without any `require(total + amount <= cap)` in the path. "
                        "The risk parameter is silently unenforced, allowing over-borrow / cap bypass "
                        "(Aave-V3 isolated-mode / bad-debt vector)."
                    ),
                    impact_score=7.0,
                    confidence_score=5.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={
                        "function": fname, "file": path, "caps": sorted(caps),
                        "bug_class": "borrow_cap_not_enforced", "needs_poc": True,
                    },
                    next_tests=[
                        "Borrow beyond the configured cap on a fork; expect it to succeed",
                        "Confirm no require compares the cap against the incremented global total",
                    ],
                    affected_functions=[fname],
                ))
        return out


class BadDebtNoSocializationDetector(Detector):
    name = "bad_debt_no_socialization"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            # Only fire when the contract has NO socialization machinery at all.
            if _DEFICIT_SINK_RE.search(source):
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if not _LIQ_FN_RE.search(fname):
                    continue
                body = strip_comments(raw_body)
                if not (_UNDERWATER_RE.search(body) and _DEBT_ZERO_RE.search(body)):
                    continue
                out.append(FindingCandidate(
                    detector="bad_debt_no_socialization",
                    title=f"Underwater liquidation clears debt with no deficit sink: {fname}",
                    description=(
                        f"`{fname}` has an underwater branch that zeroes the borrower's debt but writes down NO "
                        "deficit/reserve/badDebt anywhere in the contract, so the loss is never accounted. If "
                        "share/exchange-rate redemption still counts that debt as an asset, the last withdrawers "
                        "are left insolvent — a bank-run (Euler / isolated-market class). Socialize the residual "
                        "to reserves or write it down globally."
                    ),
                    impact_score=7.0,
                    confidence_score=4.0,  # NEEDS_MORE_INVESTIGATION lead (low confidence)
                    severity_candidate="high",
                    evidence={
                        "function": fname, "file": path, "bug_class": "bad_debt_no_socialization",
                        "needs_poc": True,
                    },
                    next_tests=[
                        "Drive a position underwater and liquidate; check whether total assets still count the cleared debt",
                        "Confirm no reserve/deficit write-down exists anywhere in the contract",
                    ],
                    affected_functions=[fname],
                ))
        return out


class HealthFactorRoundingDetector(Detector):
    """A solvency/health check that rounds the COLLATERAL side up (ceil) while the debt
    side uses plain integer division, then compares `collateral >= debt`. The asymmetric
    rounding lets a borrower read as healthy while actually underwater. Lead-only /
    low-confidence (benign helpers legitimately mix ceil and floor)."""
    name = "health_factor_rounding"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if not _HEALTH_FN_RE.search(fname):
                    continue
                body = strip_comments(raw_body)
                if not (_COLLATERAL_RE.search(body) and _DEBT_TERM_RE.search(body)):
                    continue
                if not (_CEIL_IDIOM_RE.search(body) and _GTE_RE.search(body)):
                    continue
                out.append(FindingCandidate(
                    detector="health_factor_rounding",
                    title=f"Health check rounds collateral up vs debt (favors borrower): {fname}",
                    description=(
                        f"`{fname}` computes the collateral side with a round-up (ceil) while the debt/required "
                        "side rounds toward zero, then compares `collateral >= debt`. The asymmetric rounding "
                        "lets a borrower stay 'healthy' by a wei while actually underwater, blocking liquidation "
                        "and accreting bad debt. Round collateral DOWN and debt UP (conservative)."
                    ),
                    impact_score=6.0,
                    confidence_score=3.5,  # LOW_OR_INFO (FP-prone; investigate)
                    severity_candidate="medium",
                    evidence={"function": fname, "file": path, "bug_class": "health_factor_rounding", "needs_poc": True},
                    next_tests=[
                        "Construct a position that is exactly underwater; confirm the health check still passes",
                        "Confirm the round-up is on the collateral side of the comparison",
                    ],
                    affected_functions=[fname],
                ))
        return out
