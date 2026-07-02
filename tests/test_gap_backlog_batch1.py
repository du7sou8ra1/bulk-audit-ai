"""Gap-backlog batch 1 (low-FP standalone): each positive fires, each safe variant silent."""
from pathlib import Path

from backend.detectors.account_abstraction import ValidateUserOpMissingPrefundDetector
from backend.detectors.base import TargetContext
from backend.detectors.defi_lending_extra import (
    BadDebtNoSocializationDetector,
    BorrowCapNotEnforcedDetector,
)
from backend.detectors.proxy_impl_safety import MissingStorageGapDetector
from backend.detectors.staking_extra import EmergencyWithdrawStaleDebtDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


# ---- emergency_withdraw_stale_debt ----
def test_emergency_withdraw_leaves_stale_debt_fires():
    src = """contract Chef {
      struct U { uint256 amount; uint256 rewardDebt; }
      mapping(address => U) public userInfo;
      IERC20 token;
      function emergencyWithdraw() external {
        U storage u = userInfo[msg.sender];
        uint256 amt = u.amount;
        u.amount = 0;
        token.transfer(msg.sender, amt);
      }
    }"""
    assert EmergencyWithdrawStaleDebtDetector().run(_ctx(src))


def test_emergency_withdraw_clean_silent():
    src = """contract Chef {
      struct U { uint256 amount; uint256 rewardDebt; }
      mapping(address => U) public userInfo;
      uint256 public totalStaked;
      IERC20 token;
      function emergencyWithdraw() external {
        U storage u = userInfo[msg.sender];
        uint256 amt = u.amount;
        u.amount = 0;
        u.rewardDebt = 0;
        totalStaked -= amt;
        token.transfer(msg.sender, amt);
      }
    }"""
    assert not EmergencyWithdrawStaleDebtDetector().run(_ctx(src))


# ---- borrow_cap_not_enforced ----
def test_borrow_cap_not_enforced_fires():
    src = """contract Pool {
      uint256 public borrowCap;
      uint256 public totalBorrows;
      function borrow(uint256 amount) external { totalBorrows += amount; }
    }"""
    assert BorrowCapNotEnforcedDetector().run(_ctx(src))


def test_borrow_cap_enforced_silent():
    src = """contract Pool {
      uint256 public borrowCap;
      uint256 public totalBorrows;
      function borrow(uint256 amount) external {
        require(totalBorrows + amount <= borrowCap, "cap");
        totalBorrows += amount;
      }
    }"""
    assert not BorrowCapNotEnforcedDetector().run(_ctx(src))


def test_no_cap_declared_silent():
    src = """contract Pool {
      uint256 public totalBorrows;
      function borrow(uint256 amount) external { totalBorrows += amount; }
    }"""
    assert not BorrowCapNotEnforcedDetector().run(_ctx(src))


# ---- bad_debt_no_socialization ----
def test_bad_debt_no_socialization_fires():
    src = """contract Lend {
      mapping(address => uint256) debt;
      function liquidate(address u, uint256 collateral, uint256 seized) external {
        if (collateral < debt[u]) { debt[u] = 0; }
      }
    }"""
    assert BadDebtNoSocializationDetector().run(_ctx(src))


def test_bad_debt_with_reserve_writedown_silent():
    src = """contract Lend {
      mapping(address => uint256) debt;
      uint256 public deficit;
      function liquidate(address u, uint256 collateral, uint256 seized) external {
        if (collateral < debt[u]) { deficit += debt[u] - collateral; debt[u] = 0; }
      }
    }"""
    assert not BadDebtNoSocializationDetector().run(_ctx(src))


# ---- missing_storage_gap ----
def test_missing_gap_in_abstract_upgradeable_base_fires():
    src = """abstract contract BaseUpgradeable is Initializable {
      uint256 public fee;
      address public treasury;
    }"""
    assert MissingStorageGapDetector().run(_ctx(src))


def test_gap_present_silent():
    src = """abstract contract BaseUpgradeable is Initializable {
      uint256 public fee;
      address public treasury;
      uint256[48] private __gap;
    }"""
    assert not MissingStorageGapDetector().run(_ctx(src))


def test_non_abstract_leaf_silent():
    src = """contract Leaf is Initializable {
      uint256 public fee;
    }"""
    assert not MissingStorageGapDetector().run(_ctx(src))


# ---- validateuserop_missing_prefund ----
def test_validateuserop_no_prefund_fires():
    src = """contract Acct {
      function validateUserOp(UserOp calldata u, bytes32 h, uint256 missingAccountFunds)
        external returns (uint256) { return 0; }
    }"""
    assert ValidateUserOpMissingPrefundDetector().run(_ctx(src))


def test_validateuserop_pays_prefund_silent():
    src = """contract Acct {
      function validateUserOp(UserOp calldata u, bytes32 h, uint256 missingAccountFunds)
        external returns (uint256) {
        if (missingAccountFunds > 0) { (bool ok,) = msg.sender.call{value: missingAccountFunds}(""); ok; }
        return 0;
      }
    }"""
    assert not ValidateUserOpMissingPrefundDetector().run(_ctx(src))
