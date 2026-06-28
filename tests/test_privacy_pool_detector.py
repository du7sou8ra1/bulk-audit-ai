from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.privacy_pool import PrivacyPoolDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="ultra-deep-v2",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _rules(src: str) -> set[str]:
    return {f.evidence.get("rule_id") for f in PrivacyPoolDetector().run(_ctx(src))}


def test_privacy_nullifier_after_transfer_detected():
    src = """
    contract Mixer {
      mapping(bytes32 => bool) public nullifierSpent;
      function withdraw(bytes calldata proof, bytes32 root, bytes32 nullifier, address payable recipient) external {
        require(verifyProof(proof, root, nullifier), "bad");
        require(!nullifierSpent[nullifier], "spent");
        (bool ok,) = recipient.call{value: 1 ether}(""); require(ok);
        nullifierSpent[nullifier] = true;
      }
      function verifyProof(bytes calldata, bytes32, bytes32) internal returns (bool) { return true; }
    }
    """
    assert "privacy_nullifier_marked_after_value_transfer" in _rules(src)


def test_privacy_known_root_and_cei_safe_order_not_flagged_for_order_or_root():
    src = """
    contract Mixer {
      mapping(bytes32 => bool) public nullifierSpent;
      mapping(bytes32 => bool) public roots;
      function withdraw(bytes calldata proof, bytes32 root, bytes32 nullifier, address payable recipient) external {
        require(roots[root], "root");
        require(verifyProof(proof, root, nullifier), "bad");
        require(!nullifierSpent[nullifier], "spent");
        nullifierSpent[nullifier] = true;
        (bool ok,) = recipient.call{value: 1 ether}(""); require(ok);
      }
      function verifyProof(bytes calldata, bytes32, bytes32) internal returns (bool) { return true; }
    }
    """
    rules = _rules(src)
    assert "privacy_nullifier_marked_after_value_transfer" not in rules
    assert "privacy_unknown_root_acceptance" not in rules


def test_privacy_unbounded_fee_and_missing_binding_detected():
    src = """
    contract Mixer {
      mapping(bytes32 => bool) public nullifierSpent;
      function withdraw(bytes calldata proof, bytes32 root, bytes32 nullifier, uint256 amount, uint256 fee, address payable recipient, address payable relayer) external {
        require(verifyProof(proof, root, nullifier), "bad");
        require(!nullifierSpent[nullifier], "spent");
        nullifierSpent[nullifier] = true;
        relayer.transfer(fee);
        recipient.transfer(amount - fee);
      }
      function verifyProof(bytes calldata, bytes32, bytes32) internal returns (bool) { return true; }
    }
    """
    rules = _rules(src)
    assert "privacy_public_inputs_do_not_bind_action_values" in rules
    assert "privacy_fee_unbounded_and_not_proof_bound" in rules
