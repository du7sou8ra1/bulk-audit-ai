"""AnalyzerFindingsDetector: promote Slither/Mythril/Semgrep findings to candidates.

Recall enhancement — a bug that only a native analyzer caught used to be discarded
(analyzer output was corroboration-only). Verify the adapter maps impact/confidence
correctly, attributes the source, and never auto-reaches CONFIRMED_CRITICAL.

Run: venv/Scripts/python -m pytest tests/test_analyzer_findings.py -q
"""
from pathlib import Path

from backend.core.scoring import score_finding
from backend.detectors.analyzer_findings import AnalyzerFindingsDetector
from backend.detectors.base import TargetContext
from backend.models import Classification


def _ctx(tool_outputs) -> TargetContext:
    return TargetContext(
        address="0x0000000000000000000000000000000000000001",
        chain="ethereum",
        profile="ultra-deep-v2",
        onchain=None,
        proxy_info=None,
        workspace=Path("."),
        contract_name="T",
        source_files={"T.sol": "contract T {}"},
        tool_outputs=tool_outputs,
    )


def _run(tool_outputs):
    return AnalyzerFindingsDetector().run(_ctx(tool_outputs))


def test_slither_critical_check_becomes_high_impact_candidate():
    cands = _run({"slither": {"status": "ok", "findings": [{
        "check": "reentrancy-eth", "impact": "high", "confidence": "medium",
        "description": "Reentrancy in withdraw()", "location": "T.sol:10",
        "function": "withdraw", "high_value": True,
    }]}})
    assert len(cands) == 1
    c = cands[0]
    assert c.detector == "slither:reentrancy-eth"
    assert c.impact_score == 9.0
    assert c.confidence_score <= 7.0
    assert c.affected_functions == ["withdraw"]
    assert c.evidence["source"] == "slither" and c.evidence["external_analyzer"] is True


def test_slither_alone_never_confirmed_critical_but_is_reportable():
    c = _run({"slither": {"findings": [{
        "check": "controlled-delegatecall", "impact": "high", "confidence": "high",
        "description": "Controlled delegatecall", "function": "exec", "high_value": True,
    }]}})[0]
    score = score_finding(c, [], profile="ultra-deep-v2")
    # impact 9 + capped confidence -> LIKELY_CRITICAL_NEEDS_POC, NOT CONFIRMED_CRITICAL.
    assert score.classification != Classification.CONFIRMED_CRITICAL
    assert score.classification == Classification.LIKELY_CRITICAL_NEEDS_POC


def test_medium_slither_finding_is_a_lead_not_critical():
    c = _run({"slither": {"findings": [{
        "check": "incorrect-equality", "impact": "medium", "confidence": "medium",
        "description": "Dangerous strict equality", "function": "check", "high_value": True,
    }]}})[0]
    assert 7.0 <= c.impact_score < 9.0  # high_value bump, but not a critical check


def test_semgrep_and_mythril_findings_are_adapted():
    cands = _run({
        "semgrep": {"findings": [{
            "check": "solidity.unchecked-call", "impact": "warning",
            "description": "unchecked call", "location": "T.sol:5"}]},
        "mythril": {"findings": [{
            "check": "", "title": "External Call To User-Supplied Address", "impact": "high",
            "confidence": "", "description": "SWC-107", "swc_id": "107"}]},
    })
    sources = {c.evidence["source"] for c in cands}
    assert sources == {"semgrep", "mythril"}


def test_no_tool_outputs_yields_nothing():
    assert _run({}) == []
    assert AnalyzerFindingsDetector().run(_ctx(None)) == []
    assert _run({"slither": {"status": "skipped", "findings": []}}) == []
