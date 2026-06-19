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

from ..detectors.base import FindingCandidate
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
}


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
    candidate: FindingCandidate, tool_findings: list[dict] | None = None
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

    # Adversarial refutation (gap #3): an independent skeptic read the code and
    # disproved exploitability -> hard-cap so it cannot reach a critical bucket.
    refutation = ev.get("refutation") or {}
    if ev.get("refuted"):
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

    conf = _clamp(conf)
    classification = (
        Classification.FALSE_POSITIVE if suppressed else _classify(impact, conf)
    )
    return ScoreResult(
        impact_score=impact,
        confidence_score=conf,
        severity_candidate=_severity_from_impact(impact),
        confidence_before_ai=_confidence_label(conf),
        classification=classification,
        score_notes=notes,
    )
