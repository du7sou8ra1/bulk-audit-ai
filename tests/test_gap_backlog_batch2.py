"""Gap-backlog batch 2 (medium-FP lead-only): positive fires, safe variant silent."""
from pathlib import Path

from backend.detectors.account_abstraction import SessionKeyUnscopedDetector
from backend.detectors.amm_extra import ClmmRoundingAsymmetryDetector
from backend.detectors.base import TargetContext
from backend.detectors.bridge_extra import MessageReplayNoNonceDetector, RetryDomainBindingDetector
from backend.detectors.defi_lending_extra import HealthFactorRoundingDetector
from backend.detectors.dos_patterns import PushPaymentDosDetector
from backend.detectors.signature_extra import PermitMissingDeadlineDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile="ultra-deep-v2", onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


# ---- message_replay_no_nonce ----
def test_lzreceive_no_replay_marker_fires():
    src = """contract Bridge {
      mapping(address => uint256) public balanceOf;
      function lzReceive(uint32 srcEid, bytes32 guid, bytes calldata payload) external {
        (address to, uint256 amt) = abi.decode(payload, (address, uint256));
        balanceOf[to] += amt;
      }
    }"""
    assert MessageReplayNoNonceDetector().run(_ctx(src))


def test_lzreceive_with_processed_marker_silent():
    src = """contract Bridge {
      mapping(address => uint256) public balanceOf;
      mapping(bytes32 => bool) public processed;
      function lzReceive(uint32 srcEid, bytes32 guid, bytes calldata payload) external {
        require(!processed[guid], "replay");
        processed[guid] = true;
        (address to, uint256 amt) = abi.decode(payload, (address, uint256));
        balanceOf[to] += amt;
      }
    }"""
    assert not MessageReplayNoNonceDetector().run(_ctx(src))


# ---- retry_domain_binding ----
def test_retry_trusts_origin_fires():
    src = """contract B {
      mapping(uint32 => bytes32) peers;
      mapping(address => uint256) balances;
      function retryMessage(uint32 srcEid, bytes32 sender, uint64 nonce, address to, uint256 amt) external {
        require(peers[srcEid] == sender, "auth");
        balances[to] += amt;
      }
    }"""
    assert RetryDomainBindingDetector().run(_ctx(src))


def test_retry_only_endpoint_silent():
    src = """contract B {
      mapping(address => uint256) balances;
      modifier onlyEndpoint() { require(msg.sender == endpoint); _; }
      address endpoint;
      function retryMessage(uint32 srcEid, bytes32 sender, uint64 nonce, address to, uint256 amt) external onlyEndpoint {
        balances[to] += amt;
      }
    }"""
    assert not RetryDomainBindingDetector().run(_ctx(src))


# ---- session_key_unscoped ----
def test_session_key_unscoped_fires():
    src = """contract Validator {
      struct Session { uint48 validUntil; bool active; }
      mapping(bytes32 => Session) sessions;
      function validate(bytes32 key, bytes calldata callData) external view returns (uint256) {
        Session memory s = sessions[key];
        require(s.active && block.timestamp < s.validUntil);
        (address target, uint256 value, bytes4 selector) = abi.decode(callData, (address, uint256, bytes4));
        return 0;
      }
    }"""
    assert SessionKeyUnscopedDetector().run(_ctx(src))


def test_session_key_scoped_silent():
    src = """contract Validator {
      struct Session { uint48 validUntil; bool active; }
      mapping(bytes32 => Session) sessions;
      mapping(bytes32 => mapping(address => bool)) allowedTargets;
      function validate(bytes32 key, bytes calldata callData) external view returns (uint256) {
        Session memory s = sessions[key];
        require(s.active);
        (address target, uint256 value, bytes4 selector) = abi.decode(callData, (address, uint256, bytes4));
        require(target == approvedTarget);
        return 0;
      }
      address approvedTarget;
    }"""
    assert not SessionKeyUnscopedDetector().run(_ctx(src))


# ---- permit_missing_deadline ----
def test_permit_missing_deadline_check_fires():
    src = """contract T {
      address owner;
      function permit(address o, address s, uint256 v, uint256 deadline, uint8 vv, bytes32 r, bytes32 ss) external {
        bytes32 d = keccak256(abi.encode(o, s, v, deadline));
        require(ecrecover(d, vv, r, ss) == owner);
      }
    }"""
    assert PermitMissingDeadlineDetector().run(_ctx(src))


def test_permit_with_deadline_check_silent():
    src = """contract T {
      address owner;
      function permit(address o, address s, uint256 v, uint256 deadline, uint8 vv, bytes32 r, bytes32 ss) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 d = keccak256(abi.encode(o, s, v, deadline));
        require(ecrecover(d, vv, r, ss) == owner);
      }
    }"""
    assert not PermitMissingDeadlineDetector().run(_ctx(src))


# ---- health_factor_rounding ----
def test_health_factor_ceil_collateral_fires():
    src = """contract L {
      function isHealthy(uint256 collateral, uint256 debt, uint256 price) public pure returns (bool) {
        uint256 collValue = mulDivRoundingUp(collateral, price, 1e18);
        return collValue >= debt;
      }
      function mulDivRoundingUp(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) { return (a*b + d - 1)/d; }
    }"""
    assert HealthFactorRoundingDetector().run(_ctx(src))


def test_health_factor_plain_silent():
    src = """contract L {
      function isHealthy(uint256 collateral, uint256 debt, uint256 price) public pure returns (bool) {
        uint256 collValue = collateral * price / 1e18;
        return collValue >= debt;
      }
    }"""
    assert not HealthFactorRoundingDetector().run(_ctx(src))


# ---- clmm_rounding_asymmetry ----
def test_clmm_payout_ceil_deposit_floor_fires():
    src = """contract Pool {
      uint160 sqrtPriceX96;
      function mint(uint256 liquidity, uint256 price) external returns (uint256) { return liquidity * price / 1e18; }
      function collect(uint256 liquidity, uint256 price) external returns (uint256) { return mulDivRoundingUp(liquidity, price, 1e18); }
      function mulDivRoundingUp(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) { return (a*b + d - 1)/d; }
    }"""
    assert ClmmRoundingAsymmetryDetector().run(_ctx(src))


def test_clmm_symmetric_silent():
    src = """contract Pool {
      uint160 sqrtPriceX96;
      function mint(uint256 liquidity, uint256 price) external returns (uint256) { return liquidity * price / 1e18; }
      function collect(uint256 liquidity, uint256 price) external returns (uint256) { return liquidity * price / 1e18; }
    }"""
    assert not ClmmRoundingAsymmetryDetector().run(_ctx(src))


# ---- push_payment_dos ----
def test_push_payment_to_prev_bidder_fires():
    src = """contract Auction {
      address public highestBidder; uint256 public highestBid;
      function bid() external payable {
        payable(highestBidder).transfer(highestBid);
        highestBidder = msg.sender;
        highestBid = msg.value;
      }
    }"""
    assert PushPaymentDosDetector().run(_ctx(src))


def test_pull_payment_silent():
    src = """contract Auction {
      address public highestBidder; uint256 public highestBid;
      mapping(address => uint256) public pendingReturns;
      function bid() external payable {
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
      }
    }"""
    assert not PushPaymentDosDetector().run(_ctx(src))
