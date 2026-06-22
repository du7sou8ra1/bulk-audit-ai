"""Detector: solvency-affecting mutation that skips a liquidity/health check (v0.5).

The Euler `donateToReserves` class. A protocol that *has* a liquidity/health check
(checkLiquidity / getAccountLiquidity / healthFactor / *Allowed hooks) applies it on
most balance/collateral/debt-mutating paths -- but one path mutates solvency state
WITHOUT it, letting an account fall below the health threshold and self-liquidate
for the dynamic-penalty discount.

We flag a function ONLY when all hold:
  1. the contract clearly has the health-check concept,
  2. the function mutates solvency-relevant state,
  3. it does not reach a health check (directly or via callees),
  4. at least one SIBLING mutator does reach one.
(4) is the asymmetry that separates a real omission from a contract that simply
enforces liquidity elsewhere. Candidate only; confirm with a fork self-liquidation PoC.
"""
from __future__ import annotations

import re

from ..core.callgraph import CallGraph
from .base import Detector, FindingCandidate, TargetContext

_HEALTH_NAME_RE = re.compile(
    r"(check.*liquidity|account.*liquidity|liquidity.*check|health.?factor|"
    r"health.?check|check.?health|solvenc|collateral.?check|check.?collateral|"
    r"require.*healthy|require.*collateral)",
    re.IGNORECASE,
)
_HEALTH_CALL_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:[Ll]iquidity|Health|Solvency|Collateral)\w*\s*\(|"
    r"\b(?:borrow|redeem|mint|seize|transfer|repay)Allowed\s*\(",
    re.IGNORECASE,
)
_SOLVENCY_WRITE_RE = re.compile(
    r"\b(?:reserves?|totalReserves|reserveBalance\w*|collateral\w*|debt\w*|"
    r"borrows?|totalBorrows?|deposits?|shares?|principal|accountBorrows?|"
    r"accountTokens?|balances?)\b\s*(?:\[[^\]]*\])?(?:\s*\.\w+)*\s*(?:[+\-*/]?=)(?!=)",
    re.IGNORECASE,
)


def _directly_checks(body: str, calls: set[str]) -> bool:
    if _HEALTH_CALL_RE.search(body):
        return True
    return any(_HEALTH_NAME_RE.search(c) for c in calls)


class SolvencyCheckDetector(Detector):
    name = "solvency_check"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        g = CallGraph.build(ctx.source_files)
        if not g.fns:
            return findings

        # Protocol gate: does this contract even have the health-check concept?
        has_health = any(_HEALTH_NAME_RE.search(name) for name in g.fns) or any(
            _HEALTH_CALL_RE.search(n.body) for n in g.fns.values()
        )
        if not has_health:
            return findings

        # reaches_health: function checks directly, by name, or via a callee.
        reaches_health: set[str] = {
            name for name, n in g.fns.items() if _directly_checks(n.body, n.calls)
        }
        reaches_health |= {name for name in g.fns if _HEALTH_NAME_RE.search(name)}
        changed, iters = True, 0
        while changed and iters < 16:
            changed, iters = False, iters + 1
            for name, n in g.fns.items():
                if name in reaches_health:
                    continue
                if n.calls & reaches_health:
                    reaches_health.add(name)
                    changed = True

        # Candidate solvency-mutators: external, non-view, write solvency state.
        mutators = [
            name for name, n in g.fns.items()
            if n.is_external
            and "view" not in n.header_tail.lower()
            and "pure" not in n.header_tail.lower()
            and _SOLVENCY_WRITE_RE.search(n.body)
        ]
        if not mutators:
            return findings
        checked = [m for m in mutators if m in reaches_health]
        unchecked = [m for m in mutators if m not in reaches_health]
        # Asymmetry required: some sibling checks, this one doesn't.
        if not checked or not unchecked:
            return findings

        for name in unchecked:
            n = g.fns[name]
            findings.append(FindingCandidate(
                detector="solvency_check",
                title=f"Solvency-affecting state mutation with no liquidity/health check: {name}",
                description=(
                    f"`{name}` mutates collateral/debt/reserve/balance state but never reaches a "
                    f"liquidity/health/solvency check, while sibling mutators in the same contract "
                    f"do ({', '.join(checked[:4])}). This is the Euler `donateToReserves` class: an "
                    f"account can be pushed below the health threshold through the unchecked path and "
                    f"then self-liquidated at a discount. The asymmetry -- siblings check, this one "
                    f"does not -- is the tell."
                ),
                impact_score=8.0, confidence_score=6.0,
                severity_candidate="high",
                evidence={
                    "function": name, "file": n.file, "snippet": n.body[:1500],
                    "bug_class": "solvency", "needs_poc": True, "unprivileged": True,
                    "checked_siblings": checked[:8],
                },
                next_tests=[
                    f"On a fork, drive an account through {name} until its liquidity goes negative",
                    "Then self-liquidate the same account and confirm a net profit",
                    "Confirm no checkLiquidity/healthFactor is enforced on this path or its callees",
                ],
                affected_functions=[name],
            ))
        return findings
