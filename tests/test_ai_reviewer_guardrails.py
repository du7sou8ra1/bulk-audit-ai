from backend.core.ai_reviewer import AIResult, _apply_post_triage_guardrails
from backend.models import Classification


def _packet(evidence=None, impact=9.0, confidence=5.0, pre_cls=None):
    return {
        "candidate": {
            "detector": "zk_verifier",
            "title": "Settlement bounded by an unbound proof count",
            "pre_ai_impact": impact,
            "pre_ai_confidence": confidence,
            "pre_ai_classification": pre_cls or Classification.NEEDS_MORE_INVESTIGATION,
        },
        "evidence": evidence or {},
        "onchain_checks": {},
    }


def test_lead_only_false_positive_is_floored_to_investigation():
    result = AIResult(
        classification=Classification.FALSE_POSITIVE,
        why_not_higher="model could not confirm exploitability",
    )
    _apply_post_triage_guardrails(
        _packet({"lead_only": True, "onchain_detectable": "lead_only"}),
        result,
    )
    assert result.classification == Classification.NEEDS_MORE_INVESTIGATION
    assert result.reportability == "needs_more_testing"
    assert result.enforced_downgrade


def test_corroborated_low_info_is_floored_without_concrete_control():
    result = AIResult(
        classification=Classification.LOW_OR_INFO,
        why_not_higher="needs PoC",
    )
    _apply_post_triage_guardrails(
        _packet({"corroborated": True, "corroborated_by": ["slither", "invariant_reasoner"]}),
        result,
    )
    assert result.classification == Classification.NEEDS_MORE_INVESTIGATION


def test_concrete_mitigation_allows_false_positive():
    result = AIResult(
        classification=Classification.FALSE_POSITIVE,
        why_not_higher="require binds numTxs to proof public inputs",
    )
    _apply_post_triage_guardrails(
        _packet(
            {
                "lead_only": True,
                "refuted_concrete": True,
                "refutation": {"concrete_mitigation": True},
            }
        ),
        result,
    )
    assert result.classification == Classification.FALSE_POSITIVE


def test_ordinary_low_signal_false_positive_still_allowed():
    result = AIResult(
        classification=Classification.FALSE_POSITIVE,
        why_not_higher="normal admin function",
    )
    _apply_post_triage_guardrails(
        _packet({}, impact=5.0, confidence=2.0, pre_cls=Classification.LOW_OR_INFO),
        result,
    )
    assert result.classification == Classification.FALSE_POSITIVE
