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

from .base import (
    Detector,
    FindingCandidate,
    TargetContext,
    is_ultra_profile,
    iter_function_bodies,
)

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
# ULTRA: spot price tainted into a lending sink even without a "price" word nearby.
_LENDING_SINK_RE = re.compile(r"\b(_?mint|borrow|liquidat|seize|redeem|setcollateral)\w*", re.IGNORECASE)

# ORC-MEDIAN-SPOT: an aggregated oracle (median/min/max of N feeds) is only as safe
# as its weakest manipulable input. UwU Lend ($23M): median of 11 feeds, several raw
# Curve get_p spot reads.
_SPOT_SUBREAD_RE = re.compile(
    r"get_p\s*\(|get_dy\s*\(|\.slot0\s*\(|getReserves\s*\(|getAmountsOut\s*\(|"
    r"price_oracle\s*\(|last_price\s*\(|spotPrice",
    re.IGNORECASE,
)
_AGG_RE = re.compile(r"\b(median|mean|average)\s*\(|\bsort\s*\(|\bmin\s*\(|\bmax\s*\(", re.IGNORECASE)
_TWAP_WRAP_RE = re.compile(
    r"twap|cumulative|observe\s*\(|consult\s*\([^)]*,\s*\d+|time.?weighted", re.IGNORECASE
)
# ORC-4626-DONATION: shares = assets * supply / totalAssets where totalAssets is a
# live balanceOf(this) (donation-inflatable) with no dead-shares / virtual offset.
_SHARE_MULDIV_RE = re.compile(
    r"(assets?|amount|deposit\w*)\w*\s*\*\s*\w*supply\w*\s*/"
    r"|convertToShares\s*\(|previewDeposit\s*\(",
    re.IGNORECASE,
)
_BAL_TOTALASSETS_RE = re.compile(
    r"(asset\w*\.)?balanceOf\s*\(\s*(address\s*\(\s*this\s*\)|this)\s*\)", re.IGNORECASE
)
_VAULT_MITIGATION_RE = re.compile(
    r"_decimalsOffset|virtualShares|10\s*\*\*\s*_?decimals|MINIMUM_LIQUIDITY|deadShares|"
    r"_mint\s*\(\s*(address\s*\(\s*0\s*\)|DEAD|0xdead|0x0+dead)|require\s*\([^)]*shares\s*>=",
    re.IGNORECASE,
)


class OracleManipulationDetector(Detector):
    name = "oracle_manipulation"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        text = ctx.all_source_text()
        if not text:
            return []
        low = text.lower()
        ultra = is_ultra_profile(getattr(ctx, "profile", ""))
        if sum(1 for mk in _DEFI_MARKERS if mk in low) < 2:
            return []

        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, tail, body in iter_function_bodies(source):
                lname = fname.lower()
                # 1) spot price feeding a valuation/reward
                if _SPOT_RE.search(body) and (_PRICEY_RE.search(body)
                        or (ultra and _LENDING_SINK_RE.search(body))):
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Spot AMM price used for valuation without TWAP: {fname}",
                        desc=(f"`{fname}` reads a spot AMM price (slot0/getReserves/getAmountsOut) "
                              "and uses it in a price/value/reward calculation. Spot prices are "
                              "flash-loan manipulable within a single transaction (YieldBlox/Venus/"
                              "BlindBox class). A TWAP or a manipulation-resistant oracle is needed."),
                        impact=8.5, conf=(7.0 if ultra else 5.0), bug="oracle",
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
                # 4) balanceOf-derived pricing (donation / flash-loan); skip when a
                # virtual-offset / dead-shares mitigation is present (OZ4626).
                if _BAL_PRICE_RE.search(body) and _PRICEY_RE.search(body) \
                        and not _VAULT_MITIGATION_RE.search(body):
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Share/price derived from live balanceOf: {fname}",
                        desc=(f"`{fname}` derives a price/share/reward from a live token "
                              "balanceOf. This is inflatable by a direct donation or flash loan "
                              "(first-depositor / exchange-rate manipulation, the Venus class)."),
                        impact=8.0, conf=4.5, bug="oracle",
                        tests=["Donate tokens to the contract on a fork, then check share price moved",
                               "Confirm accounting uses internal tracked balances, not balanceOf"]))
                # 5) aggregated oracle (median/min/max) with >=1 raw spot sub-read (UwU)
                if (_PRICEY_RE.search(body) or _PRICEY_RE.search(lname)) and _AGG_RE.search(body) \
                        and _SPOT_SUBREAD_RE.search(body) and not _TWAP_WRAP_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, tier="confirmable", rule_id="oracle_aggregated_spot",
                        title=f"Aggregated oracle (median/min/max) includes a raw spot read: {fname}",
                        desc=(f"`{fname}` aggregates several price feeds (median/min/max) but at "
                              "least one input is a raw spot read (Curve get_p/get_dy, slot0, "
                              "getReserves). A median is only as safe as its weakest manipulable "
                              "minority — skewing enough of the spot inputs moves the result "
                              "(the UwU Lend $23M class)."),
                        impact=8.5, conf=6.0, bug="oracle",
                        tests=["Identify which feeds are spot vs TWAP/Chainlink; count how many an attacker can move",
                               "Fork: flash-skew the spot pools feeding this aggregate and check the output price"]))
                # 6) ERC4626 / first-depositor share inflation via balanceOf totalAssets
                if _SHARE_MULDIV_RE.search(body) and _BAL_TOTALASSETS_RE.search(body) \
                        and not _VAULT_MITIGATION_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, tier="confirmable", rule_id="share_inflation_4626",
                        title=f"ERC4626 share inflation: shares from balanceOf totalAssets, no dead-shares: {fname}",
                        desc=(f"`{fname}` computes shares = assets * supply / totalAssets where "
                              "totalAssets is a live balanceOf(address(this)) and no dead-shares / "
                              "virtual-offset mitigation is present. A first depositor can donate to "
                              "the vault to inflate totalAssets and round later deposits to zero "
                              "shares (the classic ERC4626 inflation attack)."),
                        impact=8.0, conf=6.5, bug="share_inflation",
                        tests=["Fork: deposit 1 wei, donate a large amount to the vault, then a 2nd depositor gets ~0 shares",
                               "Confirm there is no virtual-offset / minimum-liquidity dead-shares lock"]))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, bug, tests, tier=None, rule_id=None):
        ev = {"function": fname, "file": path, "snippet": body[:1500],
              "bug_class": bug, "needs_poc": True, "unprivileged": True}
        if tier:
            ev["onchain_detectable"] = tier
        if rule_id:
            ev["rule_id"] = rule_id
        return FindingCandidate(
            detector="oracle_manipulation", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="critical" if impact >= 9 else "high",
            evidence=ev, next_tests=tests, affected_functions=[fname],
        )
