"""Two roadmap upgrades:
- ReentrancyDetector callback/cross-function branch (the Penpie class: external
  call to an attacker-supplied market BEFORE the reward write).
- dedup.collapse_duplicates (the same finding from proxy+impl+flattened collapses
  to one, recording the other files).
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_reentrancy_dedup.py -q
"""
from pathlib import Path

from backend.core.dedup import collapse_duplicates
from backend.detectors.base import FindingCandidate, TargetContext
from backend.detectors.reentrancy import ReentrancyDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="ultra-deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _fired(src: str) -> set[str]:
    return {
        f.evidence.get("rule_id") or f.title
        for f in ReentrancyDetector().run(_ctx(src))
    }


def test_penpie_influenceable_callee_fires():
    src = """contract Staking {
  mapping(address=>uint) userRewards;
  function _harvestBatchMarketRewards(address[] calldata _markets) external {
    for (uint i; i < _markets.length; i++) {
      uint r = IMarket(_markets[i]).redeemRewards(address(this));
      userRewards[msg.sender] += r;
    }
  }
}"""
    assert "reentrancy_influenceable_callee" in _fired(src)


def test_penpie_guarded_and_whitelisted_silent():
    src = """contract Staking {
  mapping(address=>uint) userRewards;
  mapping(address=>bool) registeredMarkets;
  function harvest(address[] calldata _markets) external nonReentrant {
    require(registeredMarkets[_markets[0]]);
    for (uint i; i < _markets.length; i++) {
      uint r = IMarket(_markets[i]).redeemRewards(address(this));
      userRewards[msg.sender] += r;
    }
  }
}"""
    assert "reentrancy_influenceable_callee" not in _fired(src)


def test_cei_honored_callee_silent():
    # accounting write BEFORE the influenceable call -> CEI holds -> no finding
    src = """contract Staking {
  mapping(address=>uint) userRewards;
  function claim(address[] calldata _markets) external {
    userRewards[msg.sender] = 0;
    for (uint i; i < _markets.length; i++) { IMarket(_markets[i]).redeemRewards(address(this)); }
  }
}"""
    assert "reentrancy_influenceable_callee" not in _fired(src)


def _cand(file: str, snippet: str) -> FindingCandidate:
    return FindingCandidate(
        detector="d", title="X", description="", impact_score=7.0, confidence_score=5.0,
        severity_candidate="high",
        evidence={"file": file, "snippet": snippet, "rule_id": "r1"},
        affected_functions=["f"],
    )


def test_collapse_cross_file_duplicates():
    a = _cand("proxy/V.sol", "same body")
    b = _cand("impl/V.sol", "same body")
    c = _cand("other/W.sol", "other body")
    out = collapse_duplicates([a, b, c])
    assert len(out) == 2
    collapsed = [x for x in out if x.evidence.get("dup_count")]
    assert len(collapsed) == 1 and collapsed[0].evidence["dup_count"] == 2
    assert "impl/V.sol" in collapsed[0].evidence.get("also_in_files", [])


def test_distinct_bodies_not_collapsed():
    a = _cand("a.sol", "body one")
    b = _cand("b.sol", "body two")
    assert len(collapse_duplicates([a, b])) == 2
