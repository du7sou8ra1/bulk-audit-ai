"""DivideBeforeMultiplyDetector: `a / b * c` precision loss.

Positive: divide-before-multiply in value math fires (as a lead). Negatives:
multiply-before-divide, parenthesised denominator `a / (b * c)`, and power `**`
stay silent.

Run: venv/Scripts/python -m pytest tests/test_precision_loss.py -q
"""
from pathlib import Path

from backend.core.scoring import score_finding
from backend.detectors.base import TargetContext
from backend.detectors.precision_loss import DivideBeforeMultiplyDetector
from backend.models import Classification


def _run(src: str):
    ctx = TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )
    return DivideBeforeMultiplyDetector().run(ctx)


def test_divide_before_multiply_fires_and_is_a_lead():
    src = """contract Pool {
      uint256 supply; uint256 total;
      function rewardOf(uint256 amount) external view returns (uint256) { return amount / supply * total; }
    }"""
    hits = _run(src)
    assert hits and hits[0].evidence["value_context"] is True
    score = score_finding(hits[0], [], profile="ultra-deep-v2")
    # Value-context lead -> NEEDS_MORE_INVESTIGATION, never a reportable critical.
    assert score.classification == Classification.NEEDS_MORE_INVESTIGATION


def test_multiply_before_divide_is_silent():
    src = """contract Pool {
      uint256 supply; uint256 total;
      function rewardOf(uint256 amount) external view returns (uint256) { return amount * total / supply; }
    }"""
    assert not _run(src)


def test_parenthesised_denominator_is_silent():
    src = """contract C {
      function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return a / (b * c); }
    }"""
    assert not _run(src)


def test_power_operator_is_silent():
    src = """contract C {
      function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return a / b ** c; }
    }"""
    assert not _run(src)
