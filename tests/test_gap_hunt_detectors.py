"""Gap-hunt wave detectors: each positive fixture fires, each safe variant is silent.

Classes verified uncovered by the live-engine probe:
uninitialized_implementation, constructor_state_in_proxy_impl,
swap_missing_slippage_deadline, max_approve_mutable_spender, erc404_ledger_desync,
paymaster_userop_binding, userop_chainid_replay.

Run: venv/Scripts/python -m pytest tests/test_gap_hunt_detectors.py -q
"""
from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.account_abstraction import (
    PaymasterUserOpBindingDetector,
    UserOpChainIdReplayDetector,
)
from backend.detectors.defi_hygiene import (
    MaxApproveMutableSpenderDetector,
    SwapSlippageDeadlineDetector,
)
from backend.detectors.hybrid_token import Erc404LedgerDesyncDetector
from backend.detectors.proxy_impl_safety import (
    ConstructorStateInProxyImplDetector,
    UninitializedImplementationDetector,
)


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


# ---- uninitialized_implementation ----
def test_uups_missing_disable_initializers_fires():
    src = """contract V is Initializable, UUPSUpgradeable {
      address public owner;
      function initialize(address o) public initializer { owner = o; }
      function _authorizeUpgrade(address) internal override {}
    }"""
    assert UninitializedImplementationDetector().run(_ctx(src))


def test_uups_with_disable_initializers_silent():
    src = """contract V is Initializable, UUPSUpgradeable {
      address public owner;
      constructor() { _disableInitializers(); }
      function initialize(address o) public initializer { owner = o; }
      function _authorizeUpgrade(address) internal override {}
    }"""
    assert not UninitializedImplementationDetector().run(_ctx(src))


def test_non_upgradeable_contract_silent():
    src = """contract Plain { address owner; function initialize(address o) public { owner = o; } }"""
    assert not UninitializedImplementationDetector().run(_ctx(src))


# ---- constructor_state_in_proxy_impl ----
def test_immutable_in_upgradeable_impl_fires():
    src = """contract V is UUPSUpgradeable {
      uint256 public immutable FEE;
      constructor(uint256 f) { FEE = f; }
      function initialize() public initializer {}
    }"""
    assert ConstructorStateInProxyImplDetector().run(_ctx(src))


def test_upgradeable_without_immutable_silent():
    src = """contract V is UUPSUpgradeable {
      uint256 public fee;
      function initialize(uint256 f) public initializer { fee = f; }
    }"""
    assert not ConstructorStateInProxyImplDetector().run(_ctx(src))


# ---- swap_missing_slippage_deadline ----
def test_zero_minout_and_now_deadline_fires():
    src = """contract Zap {
      ISwapRouter router;
      function zap(uint256 amt) external {
        ISwapRouter.ExactInputSingleParams memory p = ISwapRouter.ExactInputSingleParams({
          tokenIn: a, tokenOut: b, fee: 3000, recipient: address(this),
          deadline: block.timestamp, amountIn: amt, amountOutMinimum: 0, sqrtPriceLimitX96: 0
        });
        router.exactInputSingle(p);
      }
    }"""
    hits = SwapSlippageDeadlineDetector().run(_ctx(src))
    assert hits and hits[0].evidence["zero_minout"] and hits[0].evidence["bad_deadline"]


def test_real_minout_and_deadline_silent():
    src = """contract Zap {
      ISwapRouter router;
      function zap(uint256 amt, uint256 minOut, uint256 deadline) external {
        ISwapRouter.ExactInputSingleParams memory p = ISwapRouter.ExactInputSingleParams({
          tokenIn: a, tokenOut: b, fee: 3000, recipient: address(this),
          deadline: deadline, amountIn: amt, amountOutMinimum: minOut, sqrtPriceLimitX96: 0
        });
        router.exactInputSingle(p);
      }
    }"""
    assert not SwapSlippageDeadlineDetector().run(_ctx(src))


# ---- max_approve_mutable_spender ----
def test_max_approve_to_setter_mutable_spender_fires():
    src = """contract V {
      IERC20 token; address public strat;
      function setStrategy(address s) external { strat = s; }
      function invest() external { token.approve(strat, type(uint256).max); }
    }"""
    hits = MaxApproveMutableSpenderDetector().run(_ctx(src))
    assert hits and hits[0].evidence["spender_var"] == "strat"


def test_max_approve_to_immutable_spender_silent():
    src = """contract V {
      IERC20 token; address public immutable strat;
      constructor(address s) { strat = s; }
      function invest() external { token.approve(strat, type(uint256).max); }
    }"""
    assert not MaxApproveMutableSpenderDetector().run(_ctx(src))


# ---- erc404_ledger_desync ----
def test_hybrid_transfer_without_nft_resync_fires():
    src = """contract T404 {
      mapping(address => uint256) public balanceOf;
      mapping(uint256 => address) public _ownerOf;
      uint256 public constant unit = 10**18;
      function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
      }
    }"""
    assert Erc404LedgerDesyncDetector().run(_ctx(src))


def test_hybrid_transfer_with_nft_resync_silent():
    src = """contract T404 {
      mapping(address => uint256) public balanceOf;
      mapping(uint256 => address) public _ownerOf;
      uint256 public constant unit = 10**18;
      function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        _transferERC721(from, to, amount / unit);
      }
      function _transferERC721(address, address, uint256) internal {}
    }"""
    assert not Erc404LedgerDesyncDetector().run(_ctx(src))


def test_pure_erc20_silent():
    src = """contract Tok {
      mapping(address => uint256) public balanceOf;
      function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount; balanceOf[to] += amount;
      }
    }"""
    assert not Erc404LedgerDesyncDetector().run(_ctx(src))


# ---- paymaster_userop_binding ----
def test_paymaster_omits_calldata_fires():
    src = """contract PM {
      address signer;
      function validatePaymasterUserOp(UserOp calldata userOp, bytes32 h, uint256 m)
        external returns (bytes memory, uint256) {
        bytes32 d = keccak256(abi.encode(userOp.sender, userOp.nonce));
        require(ecrecover(d, userOp.v, userOp.r, userOp.s) == signer);
        return ("", 0);
      }
    }"""
    assert PaymasterUserOpBindingDetector().run(_ctx(src))


def test_paymaster_binds_calldata_silent():
    src = """contract PM {
      address signer;
      function validatePaymasterUserOp(UserOp calldata userOp, bytes32 h, uint256 m)
        external returns (bytes memory, uint256) {
        bytes32 d = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
        require(ecrecover(d, userOp.v, userOp.r, userOp.s) == signer);
        return ("", 0);
      }
    }"""
    assert not PaymasterUserOpBindingDetector().run(_ctx(src))


# ---- userop_chainid_replay ----
def test_userop_local_digest_no_chainid_fires():
    src = """contract Acct {
      address owner;
      function validateUserOp(UserOp calldata userOp, bytes32 userOpHash, uint256 m)
        external returns (uint256) {
        bytes32 d = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
        require(ecrecover(d, userOp.v, userOp.r, userOp.s) == owner);
        return 0;
      }
    }"""
    assert UserOpChainIdReplayDetector().run(_ctx(src))


def test_userop_uses_entrypoint_hash_silent():
    src = """contract Acct {
      address owner;
      function validateUserOp(UserOp calldata userOp, bytes32 userOpHash, uint256 m)
        external returns (uint256) {
        require(ECDSA.recover(userOpHash, userOp.signature) == owner);
        return 0;
      }
    }"""
    assert not UserOpChainIdReplayDetector().run(_ctx(src))


def test_userop_with_chainid_silent():
    src = """contract Acct {
      address owner;
      function validateUserOp(UserOp calldata userOp, bytes32 userOpHash, uint256 m)
        external returns (uint256) {
        bytes32 d = keccak256(abi.encode(userOp.sender, userOp.nonce, block.chainid));
        require(ecrecover(d, userOp.v, userOp.r, userOp.s) == owner);
        return 0;
      }
    }"""
    assert not UserOpChainIdReplayDetector().run(_ctx(src))
