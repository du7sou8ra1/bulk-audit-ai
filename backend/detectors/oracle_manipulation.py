"""Detector: oracle / price-feed manipulation (v0.4).

Maps to 2026 incidents YieldBlox, Venus, LML, BlindBox, MakinaFi. The classic
shapes, all detectable in source:

  * SPOT price used for valuation/rewards with no TWAP — Uniswap `slot0()` /
    `getReserves()` / `getAmountsOut()` feeding a price/value/reward computation.
  * Chainlink `latestAnswer()` / `latestRoundData()` consumed with NO staleness
    (`updatedAt`) or freshness check.
  * `balanceOf(this)`-derived share price / reward (donation- and flash-loan-
    manipulable).
  * A function literally named `getTwapPrice` that reads spot (the BlindBox bug).

Candidates only. The refuter + scoring gate them; a real confirm needs the
flash-loan fork simulation (see core/flashloan_sim.py).
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies

_DEFI_MARKERS = ("price", "oracle", "reward", "share", "collateral", "swap",
                 "reserve", "twap", "value", "redeem", "borrow", "liquidat")
_SPOT_RE = re.compile(r"\.slot0\s*\(|getReserves\s*\(|getAmountsOut\s*\(|"
                      r"getAmountOut\s*\(|consult\s*\(|spotPrice|price0Cumulative",
                      re.IGNORECASE)
_CL_RE = re.compile(r"latestAnswer\s*\(|latestRoundData\s*\(", re.IGNORECASE)
_STALENESS_RE = re.compile(r"updatedAt|answeredInRound|roundId|block\.timestamp\s*-|"
                           r"staleness|heartbeat|MAX_DELAY|priceAge", re.IGNORECASE)
_BAL_PRICE_RE = re.compile(
    r"balanceOf\s*\([^)]*\)\s*[*/]|[*/]\s*[\w.]*balanceOf\s*\(", re.IGNORECASE
)
_PRICEY_RE = re.compile(r"price|value|reward|share|rate|amountOut|collateral", re.IGNORECASE)


class OracleManipulationDetector(Detector):
    name = "oracle_manipulation"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        text = ctx.all_source_text()
        if not text:
            return []
        low = text.lower()
        if sum(1 for mk in _DEFI_MARKERS if mk in low) < 2:
            return []

        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, tail, body in iter_function_bodies(source):
                lname = fname.lower()
                # 1) spot price feeding a valuation/reward
                if _SPOT_RE.search(body) and _PRICEY_RE.search(body):
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Spot AMM price used for valuation without TWAP: {fname}",
                        desc=(f"`{fname}` reads a spot AMM price (slot0/getReserves/getAmountsOut) "
                              "and uses it in a price/value/reward calculation. Spot prices are "
                              "flash-loan manipulable within a single transaction (YieldBlox/Venus/"
                              "BlindBox class). A TWAP or a manipulation-resistant oracle is needed."),
                        impact=8.5, conf=5.0, bug="oracle",
                        tests=["Fork-simulate a flash-loan that skews the pool, then call this fn",
                               "Confirm price source is TWAP/Chainlink with staleness checks"]))
                # 2) named getTwapPrice but reads spot (BlindBox)
                if "twap" in lname and _SPOT_RE.search(body):
                    findings.append(self._c(
                        fname, path, body,
                        title=f"`{fname}` claims TWAP but reads spot price",
                        desc=(f"`{fname}` is named like a TWAP getter but its body reads a spot "
                              "reserve/price (the BlindBox bug). Callers assume manipulation "
                              "resistance that isn't there."),
                        impact=8.0, conf=6.0, bug="oracle",
                        tests=["Verify the function actually time-averages over a window"]))
                # 3) Chainlink without staleness
                if _CL_RE.search(body) and not _STALENESS_RE.search(body):
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Chainlink price consumed without staleness check: {fname}",
                        desc=(f"`{fname}` uses latestAnswer/latestRoundData but no freshness "
                              "(updatedAt/answeredInRound) check was found. A stale/frozen feed "
                              "mis-prices (LML reward class)."),
                        impact=6.5, conf=5.0, bug="oracle",
                        tests=["Confirm updatedAt is checked against a max heartbeat",
                               "Confirm price > 0 and answeredInRound >= roundId"]))
                # 4) balanceOf-derived pricing (donation / flash-loan)
                if _BAL_PRICE_RE.search(body) and _PRICEY_RE.search(body):
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Share/price derived from live balanceOf: {fname}",
                        desc=(f"`{fname}` derives a price/share/reward from a live token "
                              "balanceOf. This is inflatable by a direct donation or flash loan "
                              "(first-depositor / exchange-rate manipulation, the Venus class)."),
                        impact=8.0, conf=4.5, bug="oracle",
                        tests=["Donate tokens to the contract on a fork, then check share price moved",
                               "Confirm accounting uses internal tracked balances, not balanceOf"]))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, bug, tests):
        return FindingCandidate(
            detector="oracle_manipulation", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="critical" if impact >= 9 else "high",
            evidence={"function": fname, "file": path, "snippet": body[:1500],
                      "bug_class": bug, "needs_poc": True, "unprivileged": True},
            next_tests=tests, affected_functions=[fname],
        )
