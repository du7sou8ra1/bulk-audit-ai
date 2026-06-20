"""Regression tests for the lead-finding classification fix.

The real Aztec settlement-boundary bug WAS detected (settlement_count +
value_extracted + the reasoner all fired) but the classifier stamped every one
FALSE_POSITIVE at confidence 2.0 — because the refuter/scoring treated "cannot
confirm from Solidity" as "not a bug". For a lead_only finding that is its
EXPECTED state, not a refutation. These tests pin the corrected behaviour:

  * an un-refuted, high-impact lead lands in NEEDS_MORE_INVESTIGATION (never FP),
  * a lead the refuter defused with a CITED on-chain control may still drop,
  * cross-signal corroboration raises confidence but not the verdict,
  * ordinary (non-lead) refuted findings are still hard-capped (no regression).

Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_classification.py -q
"""
from backend.core.scoring import mark_corroboration, score_finding
from backend.detectors.base import FindingCandidate
from backend.models import Classification


def _lead(impact=9.0, conf=4.0, refuted=False, fn="processRollup", detector="zk_verifier", extra=None):
    ev = {"lead_only": True, "onchain_detectable": "lead_only"}
    if refuted:
        ev["refuted"] = True
    if extra:
        ev.update(extra)
    return FindingCandidate(
        detector=detector,
        title="Settlement bounded by a caller-supplied count not bound to the proof",
        description="numTxs decoded from calldata bounds settlement; no equality check.",
        impact_score=impact,
        confidence_score=conf,
        severity_candidate="high",
        evidence=ev,
        affected_functions=[fn],
    )


def test_unrefuted_lead_is_not_a_false_positive():
    r = score_finding(_lead(impact=9.0, conf=4.0))
    assert r.classification == Classification.NEEDS_MORE_INVESTIGATION


def test_lead_low_confidence_still_surfaces():
    # Even if other signals pushed confidence to the floor, an un-refuted
    # high-impact lead must still reach the investigation bucket.
    r = score_finding(_lead(impact=9.0, conf=1.0))
    assert r.classification == Classification.NEEDS_MORE_INVESTIGATION
    assert r.confidence_score >= 3.0


def test_lead_capped_at_investigation_without_poc():
    # Corroboration + high impact must NOT auto-promote a lead to LIKELY/CONFIRMED
    # critical — it is unconfirmable from Solidity until a PoC passes.
    c = _lead(impact=9.0, conf=4.0, extra={"corroborated": True, "corroborated_by": ["invariant_reasoner"]})
    r = score_finding(c)
    assert r.classification == Classification.NEEDS_MORE_INVESTIGATION
    assert r.confidence_score >= 6.0  # +2 corroboration bump is reflected


def test_lead_with_passing_poc_can_escalate():
    c = _lead(impact=9.0, conf=6.0, extra={"poc_passed": True})
    r = score_finding(c)
    assert r.classification in (
        Classification.CONFIRMED_CRITICAL,
        Classification.LIKELY_CRITICAL_NEEDS_POC,
    )


def test_lead_defused_by_concrete_control_drops():
    # A lead the skeptic refuted by citing a concrete on-chain control IS allowed
    # to fall out of the investigation bucket.
    r = score_finding(_lead(impact=9.0, conf=4.0, refuted=True))
    assert r.classification == Classification.LOW_OR_INFO
    assert r.confidence_score <= 2.0


def test_non_lead_refuted_still_capped():
    # Regression: ordinary refuted findings keep the original hard cap.
    c = FindingCandidate(
        detector="reentrancy", title="reentrancy", description="x",
        impact_score=9.0, confidence_score=8.0, severity_candidate="critical",
        evidence={"refuted": True}, affected_functions=["withdraw"],
    )
    r = score_finding(c)
    assert r.confidence_score <= 2.0
    assert r.classification == Classification.LOW_OR_INFO


def test_corroboration_marks_shared_function():
    a = _lead(detector="zk_verifier", fn="processRollup")
    b = _lead(detector="invariant_reasoner", fn="processRollup")
    solo = _lead(detector="reentrancy", fn="someOtherFn")
    mark_corroboration([a, b, solo])
    assert a.evidence.get("corroborated") and "invariant_reasoner" in a.evidence["corroborated_by"]
    assert b.evidence.get("corroborated") and "zk_verifier" in b.evidence["corroborated_by"]
    assert not solo.evidence.get("corroborated")


def test_corroboration_confidence_bump():
    base = score_finding(_lead(impact=9.0, conf=4.0)).confidence_score
    c = _lead(impact=9.0, conf=4.0, extra={"corroborated": True, "corroborated_by": ["invariant_reasoner"]})
    bumped = score_finding(c).confidence_score
    assert bumped >= base + 2.0
