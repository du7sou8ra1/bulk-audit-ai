"""UnsafeDowncastDetector: silent-truncation narrowing casts (uintN(x)).

Positive: an unbounded param cast to a narrower type fires. Negatives: bounded /
masked / SafeCast / literal casts stay silent. Calibrated as a lead (never auto
CONFIRMED_CRITICAL).

Run: venv/Scripts/python -m pytest tests/test_unsafe_cast.py -q
"""
from pathlib import Path

from backend.core.scoring import score_finding
from backend.detectors.base import TargetContext
from backend.detectors.unsafe_cast import UnsafeDowncastDetector
from backend.models import Classification


def _run(src: str):
    ctx = TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )
    return UnsafeDowncastDetector().run(ctx)


def test_unbounded_param_downcast_fires():
    src = """contract Vault {
      mapping(address => uint128) public shares;
      function deposit(uint256 amount) external { shares[msg.sender] += uint128(amount); }
    }"""
    hits = _run(src)
    assert hits, "expected an unsafe-downcast lead"
    ev = hits[0].evidence
    assert ev["target_type"] == "uint128" and ev["variable"] == "amount"
    assert ev["from_parameter"] is True

    # Lead-level only: NEEDS_MORE_INVESTIGATION, never CONFIRMED/LIKELY critical.
    score = score_finding(hits[0], [], profile="ultra-deep-v2")
    assert score.classification == Classification.NEEDS_MORE_INVESTIGATION


def test_bounded_downcast_is_silent():
    src = """contract Vault {
      mapping(address => uint128) public shares;
      function deposit(uint256 amount) external {
        require(amount <= type(uint128).max, "overflow");
        shares[msg.sender] += uint128(amount);
      }
    }"""
    assert not _run(src)


def test_masked_downcast_is_silent():
    src = """contract C {
      function pack(uint256 x) external pure returns (uint128) { return uint128(x & type(uint128).max); }
    }"""
    assert not _run(src)


def test_safecast_is_silent():
    src = """contract C {
      using SafeCast for uint256;
      function f(uint256 x) external pure returns (uint128) { return x.toUint128(); }
    }"""
    assert not _run(src)


def test_literal_downcast_is_silent():
    src = """contract C { function f() external pure returns (uint64) { return uint64(1000); } }"""
    assert not _run(src)
