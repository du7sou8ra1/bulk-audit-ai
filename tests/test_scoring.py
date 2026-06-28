"""Tests for scoring + pre-AI classification thresholds."""
from backend.core.scoring import _classify, score_finding
from backend.detectors.base import FindingCandidate
from backend.models import Classification


def test_classify_thresholds():
    assert _classify(9, 8) == Classification.CONFIRMED_CRITICAL
    assert _classify(10, 9) == Classification.CONFIRMED_CRITICAL
    assert _classify(9, 6) == Classification.LIKELY_CRITICAL_NEEDS_POC
    assert _classify(9, 5) == Classification.LIKELY_CRITICAL_NEEDS_POC
    assert _classify(8, 4) == Classification.NEEDS_MORE_INVESTIGATION
    assert _classify(7, 3) == Classification.NEEDS_MORE_INVESTIGATION
    assert _classify(5, 9) == Classification.LOW_OR_INFO
    assert _classify(2, 1) == Classification.LOW_OR_INFO


def test_governance_finding_is_downgraded():
    """A guarded governance action should land in LOW_OR_INFO."""
    cand = FindingCandidate(
        detector="governance_blast_radius",
        title="Governance can upgrade (by design)",
        description="guarded",
        impact_score=8.0,
        confidence_score=2.0,
        severity_candidate="low",
        evidence={
            "governance_controlled": True,
            "documented_centralization": True,
            "has_access_control": True,
        },
    )
    result = score_finding(cand, tool_findings=[])
    assert result.classification == Classification.LOW_OR_INFO
    assert result.confidence_score < 4


def test_unguarded_upgrade_keeps_high_confidence():
    cand = FindingCandidate(
        detector="proxy_upgrade",
        title="Unprotected upgradeTo",
        description="no access control",
        impact_score=9.0,
        confidence_score=6.0,
        severity_candidate="critical",
        evidence={"has_access_control": False, "unguarded": ["upgradeTo"]},
    )
    result = score_finding(cand, tool_findings=[])
    assert result.classification in (
        Classification.LIKELY_CRITICAL_NEEDS_POC,
        Classification.CONFIRMED_CRITICAL,
    )


def test_tool_agreement_raises_confidence():
    cand = FindingCandidate(
        detector="arbitrary_call",
        title="delegatecall",
        description="x",
        impact_score=9.0,
        confidence_score=5.0,
        evidence={"has_access_control": False, "user_controlled_target_or_data": True},
    )
    base = score_finding(cand, tool_findings=[])
    agree = score_finding(
        cand,
        tool_findings=[{"check": "controlled-delegatecall", "description": "delegatecall to user input"}],
    )
    assert agree.confidence_score > base.confidence_score


def test_ultra_deep_floor_keeps_refuted_structural_lead():
    # The over-refutation fix: under ultra-deep a refuted STRUCTURAL lead is kept at
    # investigation level instead of being zeroed (the SOF burn-before-sync class).
    cand = FindingCandidate(
        detector="hook_pair_burn_sync", title="x", description="x",
        impact_score=9.0, confidence_score=7.0,
        evidence={"refuted": True, "onchain_detectable": "confirmable"})
    deep = score_finding(cand, [], profile="deep")
    assert deep.confidence_score <= 2.0
    assert deep.classification == Classification.LOW_OR_INFO
    ultra = score_finding(cand, [], profile="ultra-deep")
    assert ultra.confidence_score >= 4.0
    assert ultra.classification == Classification.NEEDS_MORE_INVESTIGATION
    v2 = score_finding(cand, [], profile="ultra-deep-v2")
    assert v2.confidence_score >= 4.0
    assert v2.classification == Classification.NEEDS_MORE_INVESTIGATION


def test_inert_unreferenced_value_context_caps_severity():
    cand = FindingCandidate(
        detector="approval_drain",
        title="approval drain",
        description="x",
        impact_score=9.0,
        confidence_score=8.0,
        severity_candidate="critical",
        evidence={
            "value_context": {
                "state": "no_value",
                "signal": "inert_unreferenced",
                "reference_state": "none",
            }
        },
    )
    result = score_finding(cand, [])
    assert result.classification == Classification.LOW_OR_INFO
    assert result.impact_score <= 4.0
    assert any("inert_unreferenced" in note for note in result.score_notes)


def test_unknown_value_context_never_caps_severity():
    cand = FindingCandidate(
        detector="proxy_upgrade",
        title="Unprotected upgradeTo",
        description="x",
        impact_score=9.0,
        confidence_score=8.0,
        severity_candidate="critical",
        evidence={
            "has_access_control": False,
            "unguarded": ["upgradeTo"],
            "value_context": {"state": "unknown", "signal": "unknown"},
        },
    )
    result = score_finding(cand, [])
    assert result.classification == Classification.CONFIRMED_CRITICAL
    assert any("unknown" in note for note in result.score_notes)


def test_never_initialized_caps_only_when_no_value_and_no_dependents():
    cand = FindingCandidate(
        detector="unprotected_initializer",
        title="initializer",
        description="x",
        impact_score=9.0,
        confidence_score=8.0,
        severity_candidate="critical",
        evidence={
            "never_initialized": True,
            "value_context": {"state": "no_value", "signal": "unknown", "reference_state": "none"},
        },
    )
    capped = score_finding(cand, [])
    assert capped.classification == Classification.LOW_OR_INFO

    cand.evidence["value_context"] = {"state": "unknown", "signal": "unknown"}
    unknown = score_finding(cand, [])
    assert unknown.classification == Classification.CONFIRMED_CRITICAL
