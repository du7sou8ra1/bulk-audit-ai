"""WeakRandomnessDetector: predictable block-derived PRNG.

Strong sources (prevrandao/blockhash) fire directly; weak sources fire only when
hashed / mod-reduced; plain deadline checks stay silent.

Run: venv/Scripts/python -m pytest tests/test_weak_randomness.py -q
"""
from pathlib import Path

from backend.core.scoring import score_finding
from backend.detectors.base import TargetContext
from backend.detectors.weak_randomness import WeakRandomnessDetector
from backend.models import Classification


def _run(src: str):
    ctx = TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )
    return WeakRandomnessDetector().run(ctx)


def test_prevrandao_entropy_fires_as_lead():
    src = """contract Lotto {
      address[] players;
      function draw() external view returns (address) {
        uint256 r = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao)));
        return players[r % players.length];
      }
    }"""
    hits = _run(src)
    assert hits and hits[0].evidence["strong_source"] is True
    score = score_finding(hits[0], [], profile="ultra-deep-v2")
    assert score.classification == Classification.NEEDS_MORE_INVESTIGATION


def test_weak_source_in_hash_and_modulo_fires():
    src = """contract Raffle {
      uint256 count;
      function pick(uint256 n) external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp))) % n;
      }
    }"""
    assert _run(src)


def test_plain_deadline_check_is_silent():
    src = """contract Swap {
      function go(uint256 deadline) external view { require(block.timestamp <= deadline, "expired"); }
    }"""
    assert not _run(src)


def test_block_number_height_read_is_silent():
    src = """contract C {
      function height() external view returns (uint256) { return block.number; }
    }"""
    assert not _run(src)
