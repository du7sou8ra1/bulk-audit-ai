"""Scoring + pre-AI classification.

Detectors emit a base (impact, confidence). Scoring then applies cross-signal
adjustments — tool agreement raises confidence; governance/documented-trust
lowers it — and maps the result to a classification bucket.

Classification (pre-AI), per spec:
    impact >= 9 and confidence >= 8  -> CONFIRMED_CRITICAL
    impact >= 9 and confidence 5-7   -> LIKELY_CRITICAL_NEEDS_POC
    impact >= 7 and confidence 3-5   -> NEEDS_MORE_INVESTIGATION
    else                             -> LOW_OR_INFO
"""
from __future__ import annotations

from dataclasses import dataclass

from ..detectors.base import FindingCandidate, is_ultra_profile
from ..models import Classification

# Detector -> keywords that, if present in a tool finding, count as agreement.
_TOOL_AGREEMENT_KEYWORDS = {
    "proxy_upgrade": ("upgrade", "unprotected-upgrade", "initialize", "uninitialized"),
    "arbitrary_call": (
        "delegatecall",
        "controlled-delegatecall",
        "arbitrary-send",
        "arbitrary",
        "low level call",
        "unchecked",
    ),
    "permit_misuse": ("permit", "signature", "ecrecover"),
    "timelock_roles": ("role", "access", "authorization", "owner"),
    "governance_blast_radius": (
        "upgrade",
        "owner",
        "access",
        "authorization",
        "suicidal",
        "selfdestruct",
    ),
    "bytecode_periphery": (
        "bytecode",
        "delegatecall",
        "callcode",
        "selfdestruct",
        "tx.origin",
        "approval",
        "upgrade",
        "executor",
    ),
}

# Detectors that emit STRUCTURAL findings (a concrete code pattern, not a fuzzy
# guess). Under ultra-deep the AI judge may downgrade these but not zero them.
_STRUCTURAL_DETECTORS = frozenset({
    "hook_pair_burn_sync", "reentrancy", "solvency_check", "access_control",
    "flashloan_governance", "deposit_callback_cei", "receiver_hook_credit",
    "ecrecover_zero", "eip1271_spoof", "arbitrary_from_transferfrom",
    "cross_chain_receiver_source_auth", "vault_share_donation_inflation",
    "erc2771_msgsender_spoof", "reinitializable_proxy_delegatecall",
    "payable_multicall_msgvalue_reuse", "signed_unsigned_cast_mismatch",
    "liquidation_collateral_not_cleared", "allowance_drain_router",
    "zero_value_transferfrom_bypass", "zero_transfer_reward_checkpoint",
    "erc777_hook_balance_bypass", "bridge_keeper_mutation",
    "bridge_zero_root_acceptance", "verifier_address_spoof",
    "vyper_nonreentrant_compiler", "thin_liquidity_spot_oracle",
    "lending_exchange_rate_donation", "clmm_tick_boundary_rounding",
    "invariant_precision_loss", "unsafe_mint_math",
    "flash_cycle_rounding_withdraw", "multisig_delegatecall_payload",
    "bytecode_periphery",
})


@dataclass
class ScoreResult:
    impact_score: float
    confidence_score: float
    severity_candidate: str
    confidence_before_ai: str  # low | medium | high
    classification: str
    score_notes: list[str]


def _clamp(x: float) -> float:
    return max(0.0, min(10.0, x))


def _severity_from_impact(impact: float) -> str:
    if impact >= 9:
        return "critical"
    if impact >= 7:
        return "high"
    if impact >= 4:
        return "medium"
    if impact >= 2:
        return "low"
    return "info"


def _confidence_label(conf: float) -> str:
    if conf >= 8:
        return "high"
    if conf >= 4:
        return "medium"
    return "low"


def _classify(impact: float, conf: float) -> str:
    if impact >= 9 and conf >= 8:
        return Classification.CONFIRMED_CRITICAL
    if impact >= 9 and conf >= 5:
        return Classification.LIKELY_CRITICAL_NEEDS_POC
    if impact >= 7 and conf >= 3:
        return Classification.NEEDS_MORE_INVESTIGATION
    return Classification.LOW_OR_INFO


def _tool_agreement(candidate: FindingCandidate, tool_findings: list[dict]) -> bool:
    keywords = _TOOL_AGREEMENT_KEYWORDS.get(candidate.detector, ())
    if not keywords or not tool_findings:
        return False
    for tf in tool_findings:
        blob = f"{tf.get('check', '')} {tf.get('description', '')}".lower()
        if any(k in blob for k in keywords):
            return True
    return False


def score_finding(
    candidate: FindingCandidate, tool_findings: list[dict] | None = None,
    profile: str = "deep",
) -> ScoreResult:
    tool_findings = tool_findings or []
    impact = _clamp(candidate.impact_score)
    conf = candidate.confidence_score
    ev = candidate.evidence or {}
    notes: list[str] = []

    # +2 tool agreement (Slither/Mythril/Semgrep flagged something related).
    if _tool_agreement(candidate, tool_findings):
        conf += 2
        notes.append("+2 tool agreement (static analyzer flagged a related issue)")

    # -3 governance-owner-only power.
    if ev.get("governance_controlled"):
        conf -= 3
        notes.append("-3 only governance/owner can perform the action")

    # -3 documented centralization / trust risk.
    if ev.get("documented_centralization"):
        conf -= 3
        notes.append("-3 documented centralization / trust assumption")

    # On-chain confirmation of an open/unexpected role keeps confidence up.
    if ev.get("open_roles") or ev.get("zero_address_has_role") or ev.get("dead_address_has_role"):
        conf += 1
        notes.append("+1 on-chain role read confirms open/unexpected access")

    # +2 a fork PoC showed an unprivileged caller succeed (strong evidence).
    if ev.get("poc_passed"):
        conf += 2
        notes.append("+2 fork PoC: unprivileged call succeeded on a local fork")

    # +2 cross-signal corroboration: an independent detector / the reasoner flagged
    # the SAME function. Two independent signals agreeing is much stronger than one.
    if ev.get("corroborated"):
        conf += 2
        by = ev.get("corroborated_by") or []
        notes.append(
            "+2 corroborated on the same function by: " + ", ".join(map(str, by))[:120]
        )

    # Adversarial refutation (gap #3): an independent skeptic read the code and
    # disproved exploitability -> hard-cap so it cannot reach a critical bucket.
    refutation = ev.get("refutation") or {}
    _structural = (
        candidate.detector in _STRUCTURAL_DETECTORS
        or ev.get("onchain_detectable") == "confirmable"
    )
    if ev.get("refuted"):
        if is_ultra_profile(profile) and _structural and not ev.get("suppressed"):
            # ULTRA-DEEP rank-1 floor: the AI judge may DOWNGRADE a structural
            # lead but may NOT zero it. A refuted structural finding is kept at
            # investigation level so real leads (the SOF burn-before-sync class)
            # are not buried at conf-2.0; a human must cite the actual guard.
            conf = 4.0
            notes.append(
                "ultra-deep floor: refuted STRUCTURAL lead kept at "
                "NEEDS_INVESTIGATION (AI downgrade allowed, not deletion)"
            )
        else:
            conf = min(conf, 2.0)
            notes.append(
                "capped: refuted by adversarial review — "
                + str(refutation.get("refutation", "not unprivileged-exploitable"))[:160]
            )
    elif refutation.get("attempted") and refutation.get("is_real") and not ev.get("poc_passed"):
        # Survived refutation but still unproven -> small, bounded confidence bump.
        conf += 1
        notes.append("+1 survived adversarial refutation (still needs a PoC)")

    # No PoC + no clear unauthorized path -> stay cautious (mirrors -4 signal).
    has_unauthorized_path = (
        not ev.get("has_access_control", False)
        or bool(ev.get("open_roles"))
        or bool(ev.get("unguarded"))
        or bool(ev.get("poc_passed"))
    )
    if not has_unauthorized_path and impact >= 7 and not ev.get("poc_passed"):
        conf = min(conf, 4.0)
        notes.append("capped: no demonstrated unauthorized path / no PoC")

    # FP-learning: a fingerprint the user marked false-positive is forced to FP.
    suppressed = bool(ev.get("suppressed"))
    if suppressed:
        conf = 0.0
        notes.append("suppressed: matches a user-marked false-positive fingerprint")

    # Lead-only findings encode "real risk surface, NOT confirmable from Solidity"
    # (the binding may live in the off-chain circuit / needs a fork PoC). "Cannot
    # confirm" is their EXPECTED state, not a refutation — so unless a CONCRETE
    # on-chain control defused them (refuted), keep a high-impact lead visible at
    # the investigation floor instead of letting low confidence bury it as info/FP.
    # This is exactly why the Aztec settlement-boundary lead was wrongly hidden.
    is_lead = bool(ev.get("lead_only") or ev.get("onchain_detectable") == "lead_only")
    if is_lead and not suppressed and not ev.get("refuted") and impact >= 7:
        conf = max(conf, 3.0)
        notes.append(
            "lead_only floor: unconfirmable from Solidity and not concretely "
            "refuted — kept at investigation level (a human/ZK auditor must look)"
        )

    conf = _clamp(conf)
    if suppressed:
        classification = Classification.FALSE_POSITIVE
    else:
        classification = _classify(impact, conf)
        if is_lead and not ev.get("refuted"):
            # Floor: keep a high-impact, un-refuted lead at investigation level
            # rather than letting low confidence bury it as info/FP.
            if impact >= 7 and classification in (
                Classification.LOW_OR_INFO,
                Classification.FALSE_POSITIVE,
            ):
                classification = Classification.NEEDS_MORE_INVESTIGATION
            # Ceiling: a lead is unconfirmable from Solidity, so it never claims
            # more than "needs investigation" WITHOUT a passing PoC — corroboration
            # raises confidence (visibility/sort), not the verdict.
            if not ev.get("poc_passed") and classification in (
                Classification.CONFIRMED_CRITICAL,
                Classification.LIKELY_CRITICAL_NEEDS_POC,
            ):
                classification = Classification.NEEDS_MORE_INVESTIGATION
    return ScoreResult(
        impact_score=impact,
        confidence_score=conf,
        severity_candidate=_severity_from_impact(impact),
        confidence_before_ai=_confidence_label(conf),
        classification=classification,
        score_notes=notes,
    )


def mark_corroboration(candidates: list) -> None:
    """Cross-signal agreement pass (mutates evidence in place).

    If >=2 DISTINCT detectors / the reasoner flag the SAME affected function, mark
    each of those candidates ``corroborated`` (scoring then bumps confidence).
    Independent corroboration is one of the strongest signals that a lead is real
    rather than noise — e.g. zk_verifier's settlement-boundary rule and the
    invariant_reasoner both landing on the same settlement function.
    """
    from collections import defaultdict

    by_fn: dict[str, set] = defaultdict(set)
    cands_by_fn: dict[str, list] = defaultdict(list)
    for c in candidates:
        if (getattr(c, "evidence", None) or {}).get("suppressed"):
            continue
        for fn in (getattr(c, "affected_functions", None) or []):
            if not fn:
                continue
            key = str(fn).strip().lower()
            by_fn[key].add(c.detector)
            cands_by_fn[key].append(c)
    for key, dets in by_fn.items():
        if len(dets) >= 2:
            for c in cands_by_fn[key]:
                others = sorted(d for d in dets if d != c.detector)
                if others:
                    c.evidence["corroborated"] = True
                    c.evidence["corroborated_by"] = others
