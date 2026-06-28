"""Tests for dedup / FP-learning: stable fingerprints, suppression apply, and
scoring forcing a suppressed candidate to FALSE_POSITIVE.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_dedup.py -q
"""
from sqlalchemy import select

from backend.core import dedup
from backend.core.scoring import score_finding
from backend.database import SessionLocal, init_db
from backend.detectors.base import FindingCandidate
from backend.models import Classification, SuppressedFinding


def test_fingerprint_normalizes_addresses_and_numbers():
    a = dedup.fingerprint("oracle_manipulation", "Spot price in foo (addr 0xAAA1, line 10)",
                          ["foo"], "src/V.sol")
    b = dedup.fingerprint("oracle_manipulation", "Spot price in foo (addr 0xBBB2, line 99)",
                          ["foo"], "other/path/V.sol")  # only basename matters
    assert a == b
    c = dedup.fingerprint("oracle_manipulation", "Spot price in foo", ["bar"], "V.sol")
    assert c != a  # different function => different fingerprint


def test_suppression_apply_and_scoring():
    init_db()
    cand = FindingCandidate(
        detector="oracle_manipulation", title="Spot price in foo (addr 0xAAA1, line 10)",
        description="d", impact_score=8.0, confidence_score=6.0, affected_functions=["foo"],
        evidence={"file": "src/V.sol", "bug_class": "oracle"})
    fp = dedup.candidate_fingerprint(cand)
    assert dedup.apply_suppression(cand, "0xAAA") is False  # nothing suppressed yet

    dedup.suppress(fp, address=None, detector="oracle_manipulation",
                   title="benign pattern", reason="known benign")
    # a different-but-equivalent candidate on a different contract matches the global fp
    cand2 = FindingCandidate(
        detector="oracle_manipulation", title="Spot price in foo (addr 0xBBBB, line 42)",
        description="d", impact_score=8.0, confidence_score=6.0, affected_functions=["foo"],
        evidence={"file": "V.sol"})
    assert dedup.apply_suppression(cand2, "0xBBB") is True
    res = score_finding(cand2, [])
    assert res.classification == Classification.FALSE_POSITIVE
    assert res.confidence_score == 0.0

    with SessionLocal() as db:
        for r in db.scalars(select(SuppressedFinding).where(SuppressedFinding.fingerprint == fp)).all():
            db.delete(r)
        db.commit()


def test_pattern_prior_surfaces_without_auto_suppressing():
    init_db()
    cand = FindingCandidate(
        detector="approval_drain",
        title="transferFrom may drain approvals",
        description="d",
        impact_score=8.0,
        confidence_score=6.0,
        affected_functions=["swap"],
        evidence={
            "snippet": "address from = msg.sender; token.transferFrom(from,address(this),amount);",
            "bug_class": "approval_drain",
            "refutation_pattern_class": "caller_bound_source",
        },
    )
    pattern_fp = dedup.record_pattern_refutation(cand, reason="caller-bound transferFrom source")
    cand2 = FindingCandidate(
        detector="approval_drain",
        title="transferFrom may drain approvals",
        description="d",
        impact_score=8.0,
        confidence_score=6.0,
        affected_functions=["swap"],
        evidence={
            "snippet": "address from = msg.sender; token.transferFrom(from,address(this),amount);",
            "bug_class": "approval_drain",
            "refutation_pattern_class": "caller_bound_source",
        },
    )

    assert dedup.apply_suppression(cand2, "0xBBBB") is False
    assert not cand2.evidence.get("suppressed")
    assert cand2.evidence["pattern_fingerprint"] == pattern_fp
    assert cand2.evidence["prior_pattern_refutations"]
    assert "caller-bound" in cand2.evidence["prior_refutation_reason"]

    with SessionLocal() as db:
        for r in db.scalars(select(SuppressedFinding).where(SuppressedFinding.fingerprint == pattern_fp)).all():
            db.delete(r)
        db.commit()
