"""Gap-backlog batch 3 (new standalone; cover shapes existing detectors miss)."""
from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.claim_replay_extra import ClaimReplayNoMarkerDetector
from backend.detectors.lending_accrual import InterestAccrualAsymmetryDetector
from backend.detectors.oracle_extra import TwapZeroWindowDetector
from backend.detectors.reward_math import RewardPerTokenZeroSupplyDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


# ---- interest_accrual_asymmetry ----
def test_accrual_asymmetry_fires():
    src = """contract CToken {
      uint256 public borrowIndex;
      uint256 public totalBorrows;
      function accrueInterest() public { borrowIndex = borrowIndex + 1; }
      function borrow(uint256 a) external { accrueInterest(); totalBorrows = totalBorrows + a; }
      function repay(uint256 a) external { totalBorrows = totalBorrows - a; borrowIndex = borrowIndex; }
    }"""
    hits = InterestAccrualAsymmetryDetector().run(_ctx(src))
    assert any(h.affected_functions == ["repay"] for h in hits)


def test_accrual_all_call_silent():
    src = """contract CToken {
      uint256 public borrowIndex;
      uint256 public totalBorrows;
      function accrueInterest() public { borrowIndex = borrowIndex + 1; }
      function borrow(uint256 a) external { accrueInterest(); totalBorrows = totalBorrows + a; }
      function repay(uint256 a) external { accrueInterest(); totalBorrows = totalBorrows - a; }
    }"""
    assert not InterestAccrualAsymmetryDetector().run(_ctx(src))


# ---- reward_per_token_zero_supply ----
def test_reward_per_token_no_guard_fires():
    src = """contract Staking {
      uint256 public totalSupply;
      uint256 public rewardPerTokenStored;
      uint256 public rewardRate; uint256 public lastUpdate;
      function rewardPerToken() public view returns (uint256) {
        return rewardPerTokenStored + (rewardRate * (block.timestamp - lastUpdate) * 1e18) / totalSupply;
      }
    }"""
    assert RewardPerTokenZeroSupplyDetector().run(_ctx(src))


def test_reward_per_token_with_guard_silent():
    src = """contract Staking {
      uint256 public totalSupply;
      uint256 public rewardPerTokenStored;
      uint256 public rewardRate; uint256 public lastUpdate;
      function rewardPerToken() public view returns (uint256) {
        if (totalSupply == 0) return rewardPerTokenStored;
        return rewardPerTokenStored + (rewardRate * (block.timestamp - lastUpdate) * 1e18) / totalSupply;
      }
    }"""
    assert not RewardPerTokenZeroSupplyDetector().run(_ctx(src))


# ---- twap_zero_window ----
def test_twap_zero_constant_fires():
    src = """contract Oracle {
      uint32 constant TWAP_INTERVAL = 0;
      function getPrice(address pool) external view returns (int24) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_INTERVAL;
        secondsAgos[1] = 0;
        (int56[] memory t,) = IUniswapV3Pool(pool).observe(secondsAgos);
        return int24(t[0]);
      }
    }"""
    assert TwapZeroWindowDetector().run(_ctx(src))


def test_twap_real_window_silent():
    src = """contract Oracle {
      uint32 constant TWAP_INTERVAL = 1800;
      function getPrice(address pool) external view returns (int24) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_INTERVAL;
        secondsAgos[1] = 0;
        (int56[] memory t,) = IUniswapV3Pool(pool).observe(secondsAgos);
        return int24(t[0]);
      }
    }"""
    assert not TwapZeroWindowDetector().run(_ctx(src))


# ---- claim_replay_no_marker ----
def test_claim_no_marker_fires():
    src = """contract Airdrop {
      bytes32 public merkleRoot; IERC20 token;
      function _verify(bytes32[] calldata proof, bytes32 leaf) internal view returns (bool) { return true; }
      function claim(bytes32[] calldata proof, uint256 amount) external {
        require(_verify(proof, keccak256(abi.encode(msg.sender, amount))), "bad");
        token.transfer(msg.sender, amount);
      }
    }"""
    assert ClaimReplayNoMarkerDetector().run(_ctx(src))


def test_claim_with_marker_silent():
    src = """contract Airdrop {
      bytes32 public merkleRoot; IERC20 token;
      mapping(address => bool) public claimed;
      function _verify(bytes32[] calldata proof, bytes32 leaf) internal view returns (bool) { return true; }
      function claim(bytes32[] calldata proof, uint256 amount) external {
        require(!claimed[msg.sender], "claimed");
        claimed[msg.sender] = true;
        require(_verify(proof, keccak256(abi.encode(msg.sender, amount))), "bad");
        token.transfer(msg.sender, amount);
      }
    }"""
    assert not ClaimReplayNoMarkerDetector().run(_ctx(src))
