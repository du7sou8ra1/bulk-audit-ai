"""Accuracy suite for ultra-deep v2 detectors."""
from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.ultra_deep_v2 import (
    AllowanceDrainRouterDetector,
    BridgeRetryDomainBindingDetector,
    ComponentShareAccountingDetector,
    DecimalUnitMismatchDetector,
    SettlementBoundaryMismatchDetector,
    SingleVerifierBridgeConfigDetector,
    ZeroValueTransferFromBypassDetector,
)


def _ctx(src: str, profile: str = "ultra-deep-v2") -> TargetContext:
    return TargetContext(
        address="0xabc",
        chain="ethereum",
        profile=profile,
        onchain=None,
        proxy_info=None,
        workspace=Path("."),
        contract_name="T",
        source_files={"T.sol": src},
    )


def _rules(detector, src: str) -> set[str]:
    return {f.evidence.get("rule_id") for f in detector.run(_ctx(src))}


def test_settlement_boundary_mismatch():
    bad = """
    contract Rollup {
      Verifier verifier;
      function processRollup(bytes calldata proofData, uint256 numRealTxs, bytes32[] calldata txHashes) external {
        require(verifier.verify(proofData, publicInputs()));
        for (uint256 i; i < numRealTxs; ++i) { _settle(txHashes[i]); }
      }
      function publicInputs() internal pure returns (bytes32[] memory) {}
      function _settle(bytes32) internal {}
    }
    """
    good = """
    contract Rollup {
      Verifier verifier;
      function processRollup(bytes calldata proofData, uint256 numRealTxs, bytes32[] calldata txHashes) external {
        require(numRealTxs == txHashes.length, "count");
        require(verifier.verify(proofData, publicInputs()));
        for (uint256 i; i < numRealTxs; ++i) { _settle(txHashes[i]); }
      }
      function publicInputs() internal pure returns (bytes32[] memory) {}
      function _settle(bytes32) internal {}
    }
    """
    d = SettlementBoundaryMismatchDetector()
    assert "proof_settlement_count_unbound" in _rules(d, bad)
    assert "proof_settlement_count_unbound" not in _rules(d, good)


def test_bridge_retry_domain_binding():
    bad = """
    contract Bridge {
      mapping(bytes32 => bool) processed;
      function retry(bytes calldata message) external {
        bytes32 h = keccak256(abi.encode(message));
        require(!processed[h], "done");
        processed[h] = true;
        _execute(message);
      }
      function _execute(bytes calldata) internal {}
    }
    """
    good = """
    contract Bridge {
      mapping(bytes32 => bool) processed;
      function retry(uint256 sourceChain, address sourceSender, uint256 nonce, bytes calldata message) external {
        bytes32 h = keccak256(abi.encode(block.chainid, address(this), sourceChain, sourceSender, nonce, message));
        require(!processed[h], "done");
        processed[h] = true;
        _execute(message);
      }
      function _execute(bytes calldata) internal {}
    }
    """
    d = BridgeRetryDomainBindingDetector()
    assert "bridge_retry_hash_missing_domain" in _rules(d, bad)
    assert "bridge_retry_hash_missing_domain" not in _rules(d, good)


def test_decimal_unit_mismatch():
    bad = """
    contract Lending {
      Oracle oracle;
      function collateralValue(address asset, uint256 amount) external view returns (uint256) {
        uint256 price = oracle.getPrice(asset);
        return amount * price / 1e18;
      }
    }
    """
    good = """
    contract Lending {
      Oracle oracle;
      function collateralValue(address asset, uint256 amount) external view returns (uint256) {
        uint256 price = oracle.getPrice(asset);
        uint256 scale = 10 ** IERC20Metadata(asset).decimals();
        return amount * price / scale;
      }
    }
    """
    d = DecimalUnitMismatchDetector()
    assert "oracle_math_hardcoded_scale_no_decimals" in _rules(d, bad)
    assert "oracle_math_hardcoded_scale_no_decimals" not in _rules(d, good)


def test_zero_value_transferfrom_bypass():
    bad = """
    contract Sale {
      IERC20 token;
      mapping(address => bool) claimed;
      function claimReward(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        claimed[msg.sender] = true;
        _mint(msg.sender, 100 ether);
      }
      function _mint(address, uint256) internal {}
    }
    """
    good = """
    contract Sale {
      IERC20 token;
      mapping(address => bool) claimed;
      function claimReward(uint256 amount) external {
        require(amount > 0, "zero");
        token.transferFrom(msg.sender, address(this), amount);
        claimed[msg.sender] = true;
        _mint(msg.sender, amount);
      }
      function _mint(address, uint256) internal {}
    }
    """
    d = ZeroValueTransferFromBypassDetector()
    assert "zero_transferfrom_gates_value_path" in _rules(d, bad)
    assert "zero_transferfrom_gates_value_path" not in _rules(d, good)


def test_component_share_accounting():
    bad = """
    contract IndexVault {
      address[] components;
      uint256 totalSupply;
      function redeem(uint256 shares) external {
        for (uint256 i; i < components.length; ++i) {
          uint256 amt = IERC20(components[i]).balanceOf(address(this)) * shares / totalSupply;
          IERC20(components[i]).transfer(msg.sender, amt);
        }
        _burn(msg.sender, shares);
      }
      function _burn(address, uint256) internal {}
    }
    """
    good = """
    contract IndexVault {
      address[] components;
      uint256 totalSupply;
      mapping(address => uint256) componentBalances;
      function redeem(uint256 shares) external {
        _burn(msg.sender, shares);
        for (uint256 i; i < components.length; ++i) {
          uint256 amt = componentBalances[components[i]] * shares / totalSupply;
          IERC20(components[i]).transfer(msg.sender, amt);
        }
      }
      function _burn(address, uint256) internal {}
    }
    """
    d = ComponentShareAccountingDetector()
    assert "component_redeem_live_balance_share_math" in _rules(d, bad)
    assert "component_redeem_live_balance_share_math" not in _rules(d, good)


def test_single_verifier_bridge_config():
    bad = """
    contract OAppConfig {
      function setLayerZeroConfig() external onlyOwner {
        uint256 requiredDVNCount = 1;
        address[] memory dvns = new address[](1);
        _setDVNs(requiredDVNCount, dvns);
      }
      function _setDVNs(uint256, address[] memory) internal {}
    }
    """
    good = """
    contract OAppConfig {
      function setLayerZeroConfig() external onlyOwner {
        uint256 requiredDVNCount = 3;
        address[] memory dvns = new address[](5);
        _setDVNs(requiredDVNCount, dvns);
      }
      function _setDVNs(uint256, address[] memory) internal {}
    }
    """
    d = SingleVerifierBridgeConfigDetector()
    assert "bridge_single_verifier_or_threshold_one" in _rules(d, bad)
    assert "bridge_single_verifier_or_threshold_one" not in _rules(d, good)


def test_allowance_drain_router():
    bad = """
    contract Router {
      function route(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
      }
    }
    """
    good = """
    contract Router {
      mapping(address => bool) approvedTargets;
      mapping(bytes4 => bool) allowedSelector;
      function route(address target, bytes calldata data) external {
        require(approvedTargets[target], "target");
        require(allowedSelector[bytes4(data)], "selector");
        (bool ok,) = target.call(data);
        require(ok);
      }
    }
    """
    d = AllowanceDrainRouterDetector()
    assert "router_unfiltered_target_and_calldata" in _rules(d, bad)
    assert "router_unfiltered_target_and_calldata" not in _rules(d, good)
