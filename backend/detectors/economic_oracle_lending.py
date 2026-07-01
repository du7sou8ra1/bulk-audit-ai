"""Economic oracle/lending coupling detector.

Phase 11 adds a high-signal lead for bugs that are not local arithmetic bugs in
one contract, but economic boundary failures between a price oracle and a
lending market. It is tuned for Compound UNI / UniswapAnchoredView bad-debt
style cases and the newer ERC-4626 exchange-rate-as-collateral class.

The detector deliberately emits candidates, not confirmed exploits. A real
verdict still needs the fork simulation: manipulate or advance the oracle state,
borrow against the affected collateral, then measure shortfall/bad debt.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies

_COMPOUND_ORACLE_TERMS_RE = re.compile(
    r"\b(getUnderlyingPrice|PriceOracle|Comptroller|cToken|CToken|underlying\s+price)\b",
    re.IGNORECASE,
)
_MUTABLE_PRICE_UPDATE_RE = re.compile(
    r"\b(validate|postPrices?|setPrice|setDirectPrice|pokeFailedOverPrice|"
    r"activateFailover|deactivateFailover|failover|reporter|anchorTolerance|"
    r"prices\s*\[|priceInternal)\b",
    re.IGNORECASE,
)
_BORROW_CONTEXT_RE = re.compile(
    r"\b(borrow|liquidat|collateral|getAccountLiquidity|shortfall|seize|"
    r"accountLiquidity|market|comptroller|cToken)\b",
    re.IGNORECASE,
)
_ORACLE_READ_RE = re.compile(
    r"\b(getUnderlyingPrice|priceOracle|oracle\.get|oraclePrice|assetPrice|"
    r"convertToAssets|previewRedeem|exchangeRate|totalAssets)\b",
    re.IGNORECASE,
)
_BORROW_SINK_RE = re.compile(
    r"\b(borrow|liquidat|seize|enterMarkets|mint|redeemUnderlying)\w*\s*\(",
    re.IGNORECASE,
)
_LIQUIDITY_RE = re.compile(
    r"\b(getAccountLiquidity|accountLiquidity|shortfall|collateralFactor|"
    r"maxBorrow|borrowCapacity|healthFactor|ltv)\b",
    re.IGNORECASE,
)
_ERC4626_RATE_PRICE_RE = re.compile(
    r"\b(convertToAssets|previewRedeem|totalAssets|totalSupply|balanceOf\s*\()\b",
    re.IGNORECASE,
)
_PRICE_FUNCTION_RE = re.compile(
    r"price|oracle|getUnderlyingPrice|getPrice|assetPrice|collateralValue|quote",
    re.IGNORECASE,
)
_CIRCUIT_BREAKER_RE = re.compile(
    r"\b(maxStale|staleness|updatedAt|answeredInRound|heartbeat|sequencer|"
    r"circuitBreaker|pauseGuardian|borrowPaused|marketPaused|oracleGuard|"
    r"maxDeviation|sanePrice|killSwitch|failClosed)\b",
    re.IGNORECASE,
)
_TWAP_RE = re.compile(r"\b(twap|timeWeighted|observe\s*\(|cumulative|anchorPeriod)\b", re.IGNORECASE)


def _window(source: str, needle: re.Pattern[str], *, before: int = 450, after: int = 1600) -> str:
    match = needle.search(source or "")
    if not match:
        return (source or "")[:1800]
    start = max(0, match.start() - before)
    end = min(len(source), match.end() + after)
    return source[start:end]


def _has_compound_oracle_body(source: str) -> bool:
    return any(name.lower() == "getunderlyingprice" for name, _params, _tail, _body in iter_function_bodies(source))


class EconomicOracleLendingDetector(Detector):
    name = "economic_oracle_lending"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        text = ctx.all_source_text()
        if not text:
            return []
        if not (_COMPOUND_ORACLE_TERMS_RE.search(text) or _BORROW_CONTEXT_RE.search(text)):
            return []

        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            if _has_compound_oracle_body(source):
                findings.extend(self._compound_price_oracle_findings(path, source, text))
            findings.extend(self._lending_flow_findings(path, source))
            findings.extend(self._erc4626_lending_oracle_findings(path, source, text))
        return findings

    def _compound_price_oracle_findings(self, path: str, source: str, all_text: str) -> list[FindingCandidate]:
        if not _COMPOUND_ORACLE_TERMS_RE.search(source + "\n" + all_text):
            return []
        if not _MUTABLE_PRICE_UPDATE_RE.search(source):
            return []

        has_twap = bool(_TWAP_RE.search(source))
        has_circuit = bool(_CIRCUIT_BREAKER_RE.search(source))
        confidence = 7.0
        if has_twap:
            confidence -= 0.7
        if has_circuit:
            confidence -= 0.8
        confidence = max(5.8, confidence)

        body = ""
        for name, _params, _tail, fn_body in iter_function_bodies(source):
            if name.lower() == "getunderlyingprice":
                body = fn_body
                break

        return [FindingCandidate(
            detector=self.name,
            title="Compound-style lending oracle controls borrow capacity; bad-debt scenario needs fork check",
            description=(
                "This contract exposes `getUnderlyingPrice(address)` in the Compound/Comptroller price-oracle shape "
                "and also contains mutable reporter/anchor/failover price-update logic. If the connected lending market "
                "lets borrow/liquidation decisions consume this price without a same-boundary solvency, freshness, or "
                "circuit-breaker invariant, a price update/manipulation can create under-collateralized debt. This is the "
                "Compound UNI / UniswapAnchoredView incident family and overlaps with newer exchange-rate collateral bugs."
            ),
            impact_score=8.8,
            confidence_score=confidence,
            severity_candidate="high",
            evidence={
                "rule_id": "compound_oracle_lending_bad_debt",
                "bug_class": "economic_oracle_lending",
                "incident_family": "Compound UNI / oracle-lending bad debt",
                "file": path,
                "function": "getUnderlyingPrice",
                "snippet": (body or _window(source, re.compile(r"getUnderlyingPrice", re.I)))[:1800],
                "compound_price_oracle": True,
                "has_twap_or_anchor_signal": has_twap,
                "has_local_circuit_breaker_signal": has_circuit,
                "needs_poc": True,
                "unprivileged": True,
                "onchain_detectable": "lead_only",
            },
            next_tests=[
                "Scan the connected Comptroller/cToken market and confirm borrow/liquidation reads this oracle price.",
                "Fork: manipulate or advance the reported/anchor price, borrow the affected collateral asset, then measure account shortfall/bad debt.",
                "Check whether oracle updates and borrow/liquidation can happen in the same block before a pause/guardian/circuit breaker reacts.",
            ],
            affected_functions=["getUnderlyingPrice"],
        )]

    def _lending_flow_findings(self, path: str, source: str) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for fname, _params, _tail, body in iter_function_bodies(source):
            if not (_ORACLE_READ_RE.search(body) and _LIQUIDITY_RE.search(body) and _BORROW_SINK_RE.search(body)):
                continue
            has_guard = bool(_CIRCUIT_BREAKER_RE.search(body))
            out.append(FindingCandidate(
                detector=self.name,
                title=f"Borrow/liquidation capacity depends on oracle price in `{fname}`",
                description=(
                    f"`{fname}` combines an oracle/exchange-rate read with account-liquidity or borrow-capacity math "
                    "and then reaches a borrow/liquidation/value-moving sink. If the oracle value is stale, manipulable, "
                    "or externally updated in the same economic window, this path can create bad debt or incomplete "
                    "liquidation."
                ),
                impact_score=8.6,
                confidence_score=6.8 if not has_guard else 5.8,
                severity_candidate="high",
                evidence={
                    "rule_id": "oracle_price_controls_borrow_capacity",
                    "bug_class": "economic_oracle_lending",
                    "file": path,
                    "function": fname,
                    "snippet": body[:1800],
                    "has_local_circuit_breaker_signal": has_guard,
                    "needs_poc": True,
                    "unprivileged": True,
                    "onchain_detectable": "lead_only",
                },
                next_tests=[
                    "Fork: skew/stale the oracle value and compare max borrow before/after the update.",
                    "Assert every borrow/liquidation path fails closed when the oracle is stale, paused, or outside deviation bounds.",
                    "Check that the protocol remains solvent after the worst allowed oracle movement and liquidation cap.",
                ],
                affected_functions=[fname],
            ))
        return out

    def _erc4626_lending_oracle_findings(self, path: str, source: str, all_text: str) -> list[FindingCandidate]:
        if not (_BORROW_CONTEXT_RE.search(all_text) and _ERC4626_RATE_PRICE_RE.search(source)):
            return []
        out: list[FindingCandidate] = []
        for fname, _params, _tail, body in iter_function_bodies(source):
            if not (_PRICE_FUNCTION_RE.search(fname) or _PRICE_FUNCTION_RE.search(body)):
                continue
            if not _ERC4626_RATE_PRICE_RE.search(body):
                continue
            has_guard = bool(_CIRCUIT_BREAKER_RE.search(body))
            out.append(FindingCandidate(
                detector=self.name,
                title=f"ERC-4626/share exchange rate appears to feed collateral pricing: `{fname}`",
                description=(
                    f"`{fname}` prices collateral using ERC-4626/share-rate style accounting (`convertToAssets`, "
                    "`totalAssets`, `totalSupply`, or raw balances) inside a source set with lending/borrow semantics. "
                    "If the wrapper's share ratio can be donated, looped, or flash-loan inflated, the lending market can "
                    "overvalue collateral and drain borrowable assets, matching the Edel Finance class."
                ),
                impact_score=8.7,
                confidence_score=6.6 if not has_guard else 5.7,
                severity_candidate="high",
                evidence={
                    "rule_id": "erc4626_exchange_rate_lending_oracle",
                    "bug_class": "economic_oracle_lending",
                    "incident_family": "Edel-style ERC4626 exchange-rate collateral oracle",
                    "file": path,
                    "function": fname,
                    "snippet": body[:1800],
                    "has_local_circuit_breaker_signal": has_guard,
                    "needs_poc": True,
                    "unprivileged": True,
                    "onchain_detectable": "lead_only",
                },
                next_tests=[
                    "Fork: donate/loop the wrapper vault to inflate convertToAssets, then borrow against the wrapped collateral.",
                    "Compare oracle price against an external market price after the inflation step.",
                    "Check supply/borrow caps, pause guards, and max exchange-rate deviation limits on the collateral market.",
                ],
                affected_functions=[fname],
            ))
        return out
