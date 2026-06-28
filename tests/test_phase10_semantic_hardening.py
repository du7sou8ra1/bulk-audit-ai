from pathlib import Path

from backend.core.semantic_index import build_semantic_index
from backend.core.taint import analyze_taint
from backend.detectors.access_control import AccessControlDetector
from backend.detectors.base import TargetContext
from backend.detectors.delegatecall import DelegatecallDetector
from backend.detectors.zk_verifier import ZkVerifierDetector


def _ctx(src: str, profile: str = "ultra-deep-v2") -> TargetContext:
    ctx = TargetContext(
        address="0xabc", chain="ethereum", profile=profile,
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )
    ctx.semantic = build_semantic_index(ctx.source_files, ctx.abi)
    ctx.taint = analyze_taint(ctx.semantic)
    return ctx


def _rules(detector, src: str) -> set[str]:
    return {f.evidence.get("rule_id") or f.evidence.get("bug_class") for f in detector.run(_ctx(src))}


def test_delegatecall_admin_set_storage_mapping_is_suppressed():
    src = """
    contract Router {
      address owner;
      mapping(bytes4 => address) public implementations;
      function setImplementation(bytes4 selector, address impl) external { require(msg.sender == owner, "owner"); implementations[selector] = impl; }
      function exec(bytes4 selector, bytes calldata data) external {
        (bool ok,) = implementations[selector].delegatecall(data); require(ok);
      }
    }
    """
    findings = DelegatecallDetector().run(_ctx(src))
    assert not findings


def test_delegatecall_public_setter_mapping_still_fires():
    src = """
    contract Router {
      mapping(bytes4 => address) public implementations;
      function setImplementation(bytes4 selector, address impl) external { implementations[selector] = impl; }
      function exec(bytes4 selector, bytes calldata data) external {
        (bool ok,) = implementations[selector].delegatecall(data); require(ok);
      }
    }
    """
    findings = DelegatecallDetector().run(_ctx(src))
    assert findings
    assert findings[0].evidence["user_controlled_target_or_data"] is True


def test_access_control_inline_custom_mapping_guard_suppresses_ultra_fp():
    src = """
    contract Fees {
      mapping(address => bool) controllers;
      uint256 public fee;
      function setFee(uint256 newFee) external {
        require(controllers[msg.sender], "controller");
        fee = newFee;
      }
    }
    """
    findings = [f for f in AccessControlDetector().run(_ctx(src)) if "no access control" in f.title.lower()]
    assert not findings


def test_zk_semantic_taint_cross_function_value_binding_lead():
    src = """
    interface IV { function verifyProof(bytes calldata, uint256[] calldata) external returns (bool); }
    contract Rollup {
      IV verifier;
      function withdraw(bytes calldata proof, uint256[] calldata pub, address payable recipient, uint256 amount) external {
        require(verifier.verifyProof(proof, pub), "bad proof");
        _pay(recipient, amount);
      }
      function _pay(address payable recipient, uint256 amount) internal {
        (bool ok,) = recipient.call{value: amount}(""); require(ok);
      }
    }
    """
    rules = _rules(ZkVerifierDetector(), src)
    assert "semantic_taint_proof_to_value_unbound" in rules
