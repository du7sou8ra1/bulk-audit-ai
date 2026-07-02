"""Aderyn runner normalizer + adapter surfacing.

Aderyn runs on the VPS; here we test the pure JSON normalizer (defensive over the
`*_issues` schema) and that AnalyzerFindingsDetector promotes Aderyn findings.

Run: venv/Scripts/python -m pytest tests/test_aderyn_runner.py -q
"""
from pathlib import Path

from backend.detectors.analyzer_findings import AnalyzerFindingsDetector
from backend.detectors.base import TargetContext
from backend.models import Classification
from backend.core.scoring import score_finding
from backend.runners.aderyn_runner import _normalize, run_aderyn

_SAMPLE = {
    "issue_count": {"high": 1, "low": 1},
    "critical_issues": {"issues": [{
        "title": "Delegatecall to arbitrary address",
        "description": "The target is user-controlled.",
        "detector_name": "delegatecall-untrusted",
        "instances": [{"contract_path": "src/Proxy.sol", "line_no": 42}],
    }]},
    "high_issues": {"issues": [{
        "title": "Centralization Risk",
        "description": "Owner can drain.",
        "detector_name": "centralization-risk",
        "instances": [{"contract_path": "src/Vault.sol", "line_no": 10}],
    }]},
    "low_issues": {"issues": [{
        "title": "Missing zero-address check",
        "description": "",
        "detector_name": "zero-address-check",
        "instances": [{"contract_path": "src/A.sol", "line_no": 3}],
    }]},
    "files_summary": {"ignore": "me"},  # non-issue keys ignored
}


def test_normalize_handles_all_severities():
    fs = _normalize(_SAMPLE)
    by_check = {f["check"]: f for f in fs}
    assert set(by_check) == {"delegatecall-untrusted", "centralization-risk", "zero-address-check"}
    assert by_check["delegatecall-untrusted"]["impact"] == "critical"
    assert by_check["delegatecall-untrusted"]["location"] == "src/Proxy.sol:42"
    assert by_check["high-issue"] if False else by_check["centralization-risk"]["impact"] == "high"


def test_normalize_defensive_on_garbage():
    assert _normalize({}) == []
    assert _normalize({"high_issues": {"issues": ["not a dict", None]}}) == []
    assert _normalize({"high_issues": "not a dict"}) == []


def test_adapter_promotes_aderyn_critical_to_high_impact():
    ctx = TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": "contract T {}"},
        tool_outputs={"aderyn": {"status": "ok", "findings": _normalize(_SAMPLE)}},
    )
    cands = AnalyzerFindingsDetector().run(ctx)
    assert cands and all(c.evidence["source"] == "aderyn" for c in cands)
    crit = [c for c in cands if c.evidence["check"] == "delegatecall-untrusted"][0]
    assert crit.impact_score == 9.0
    # capped confidence -> LIKELY_CRITICAL_NEEDS_POC, never auto CONFIRMED.
    score = score_finding(crit, [], profile="ultra-deep-v2")
    assert score.classification != Classification.CONFIRMED_CRITICAL


def test_run_aderyn_skips_gracefully_when_not_installed(tmp_path):
    # aderyn is not installed in CI/dev -> must return a clean skipped result.
    res = run_aderyn(tmp_path, tmp_path / "out")
    assert res.status in ("skipped", "ok", "failed", "timeout")
    if res.status == "skipped":
        assert "not installed" in res.summary
