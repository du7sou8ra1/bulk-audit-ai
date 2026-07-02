"""Precision (false-positive) regression gate.

exploit_benchmark proves recall; this proves precision — safe/benign code must not
yield reportable findings. Seeded from the batch-130 audit (100% FP Base scan) and
the IDEAS.md FP-reduction list. A failure here is a real deterministic false
positive, not an AI-dependent one.

Run: venv/Scripts/python -m pytest tests/test_precision_benchmark.py -q
"""
import pytest

from backend.core.precision_benchmark import (
    PRECISION_NEGATIVE_CASES,
    run_precision_case,
    run_precision_cases,
    precision_report,
)


@pytest.mark.parametrize("case", PRECISION_NEGATIVE_CASES, ids=lambda c: c.id)
def test_negative_case_produces_no_reportable_finding(case):
    result = run_precision_case(case)
    assert result.passed, (
        f"{case.id} produced reportable false positive(s): "
        + "; ".join(
            f"{f['detector']}::{f['classification']} (i={f['impact']} c={f['confidence']}) {f['title']}"
            for f in result.reportable_findings
        )
        + f"  [reason it should be silent: {case.reason}]"
    )


def test_precision_suite_is_clean():
    report = precision_report(run_precision_cases())
    assert report["failed_cases"] == 0, report
    assert report["total_reportable_false_positives"] == 0


def test_custom_guard_modifier_is_recognized_by_arithmetic_logic():
    """Direct regression for the batch-130 FP: mint/burn behind a custom onlyBridge
    modifier must not be flagged 'no access control' by arithmetic_logic."""
    from pathlib import Path
    from backend.detectors.arithmetic_logic import ArithmeticLogicDetector
    from backend.detectors.base import TargetContext

    src = """pragma solidity ^0.8.0;
contract T {
  address public bridge;
  mapping(address => uint256) public balanceOf;
  modifier onlyBridge() { require(msg.sender == bridge, "b"); _; }
  function mint(address to, uint256 a) external onlyBridge { balanceOf[to] += a; }
}"""
    ctx = TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )
    hits = [f for f in ArithmeticLogicDetector().run(ctx) if "no access control" in f.title]
    assert not hits, f"custom onlyBridge guard not recognized: {[f.title for f in hits]}"


def test_cli_benchmark_precision_offline_is_clean():
    from backend.main import main
    assert main(["benchmark-precision", "--list-cases"]) == 0
    assert main(["benchmark-precision"]) == 0  # offline fixtures: 0 => all clean


def test_corpus_loader_roundtrip(tmp_path):
    import json
    from backend.core.precision_benchmark import load_precision_corpus

    p = tmp_path / "corpus.json"
    p.write_text(json.dumps([
        {"id": "x", "name": "L1 token on Base", "chain": "base",
         "address": "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9",
         "label": "not_deployed", "reason": "no code on base"}
    ]), encoding="utf-8")
    cases = load_precision_corpus(p)
    assert len(cases) == 1
    assert cases[0].chain == "base" and cases[0].address.startswith("0x7Fc665")
