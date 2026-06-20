"""Accuracy suite for the rebuilt ZK vulnerability detector.

Every rule ships with a POSITIVE fixture (vulnerable Solidity that MUST trigger
the rule) and a NEGATIVE fixture (safe Solidity of the same shape that MUST NOT).
The negative fixtures are the false-positive gate — they are what let us *measure*
accuracy instead of asserting it. Each finding carries evidence["rule_id"], so we
check the exact rule fires on its positive and stays silent on its negative.

Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_zk_detector.py -q
"""
from pathlib import Path

import pytest

from backend.detectors.base import TargetContext
from backend.detectors.zk_verifier import ZkVerifierDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="zk-focused",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _fired(src: str) -> set[str]:
    return {
        f.evidence.get("rule_id")
        for f in ZkVerifierDetector().run(_ctx(src))
        if f.evidence.get("rule_id")
    }


# --------------------------------------------------------------------------- #
# (rule_id, positive_fixture, negative_fixture)
# --------------------------------------------------------------------------- #
FIXTURES: list[tuple[str, str, str]] = [
    (
        "forced_exit_released_value_unbound_to_proof",
        """pragma solidity ^0.8.0;
contract Rollup {
  mapping(bytes32=>bool) public nullifierSpent;
  function verify(bytes calldata p, uint256 id) internal returns(bool){return p.length>0;}
  function escapeHatch(bytes calldata proof, uint256 proofId, uint256 publicOutput, address payable to) external {
    require(verify(proof, proofId), "bad proof");
    require(!nullifierSpent[bytes32(proofId)]); nullifierSpent[bytes32(proofId)] = true;
    (bool ok,) = to.call{value: publicOutput}(""); require(ok);
  }
}""",
        """pragma solidity ^0.8.0;
contract Rollup {
  mapping(bytes32=>uint256) public deposits; mapping(bytes32=>bool) public nullifierSpent;
  function verify(bytes calldata p, uint256 id) internal returns(bool){return p.length>0;}
  function escapeHatch(bytes calldata proof, uint256 proofId, address payable to) external {
    require(verify(proof, proofId), "bad proof");
    bytes32 id = bytes32(proofId); require(!nullifierSpent[id]);
    uint256 amount = deposits[id]; require(amount > 0); nullifierSpent[id] = true; deposits[id]=0;
    (bool ok,) = to.call{value: amount}(""); require(ok);
  }
}""",
    ),
    (
        "exit_commitment_omits_or_redirects_recipient",
        """pragma solidity ^0.8.0;
interface IVerifier { function Verify(bytes calldata,uint256[] memory) external returns(bool); }
contract Exit { IVerifier verifier; mapping(address=>uint256) bal;
  function performExit(uint256 root, uint48 acc, address to, uint128 amount, bytes calldata proof) external {
    bytes32 c = keccak256(abi.encodePacked(root, acc, amount));
    uint256[] memory inputs = new uint256[](1); inputs[0] = uint256(c);
    require(verifier.Verify(proof, inputs), "bad"); bal[to] += amount;
  }
}""",
        """pragma solidity ^0.8.0;
interface IVerifier { function Verify(bytes calldata,uint256[] memory) external returns(bool); }
contract Exit { IVerifier verifier; mapping(address=>uint256) bal;
  function performExit(uint256 root, uint48 acc, address to, uint128 amount, bytes calldata proof) external {
    bytes32 c = keccak256(abi.encodePacked(root, acc, to, amount));
    uint256[] memory inputs = new uint256[](1); inputs[0] = uint256(c);
    require(verifier.Verify(proof, inputs), "bad"); bal[to] += amount;
  }
}""",
    ),
    (
        "withdrawal_fee_relayer_unbound_or_unbounded",
        """pragma solidity ^0.8.0;
interface IV { function verify(bytes calldata,uint256[] calldata) external view returns(bool); }
contract Mixer { IV v; mapping(bytes32=>bool) spent;
  function withdraw(bytes calldata pf, uint256[] calldata pub, bytes32 nf, uint256 amount, uint256 fee, address payable recipient, address payable relayer) external {
    require(v.verify(pf, pub), "bad"); require(!spent[nf]); spent[nf]=true;
    relayer.transfer(fee); recipient.transfer(amount - fee);
  }
}""",
        """pragma solidity ^0.8.0;
interface IV { function verify(bytes calldata,uint256[] calldata) external view returns(bool); }
contract Mixer { IV v; mapping(bytes32=>bool) spent;
  function withdraw(bytes calldata pf, uint256[] calldata pub, bytes32 nf, uint256 amount, uint256 fee, address payable recipient, address payable relayer) external {
    require(fee <= amount, "fee>amt");
    require(v.verify(pf, pub), "bad"); require(!spent[nf]); spent[nf]=true;
    relayer.transfer(fee); recipient.transfer(amount - fee);
  }
}""",
    ),
    (
        "public_inputs_not_fed_to_verify",
        """pragma solidity ^0.8.0;
interface IV { function verifyProof(uint256[8] calldata,uint256[2] calldata) external view returns(bool); }
contract Mixer { IV v; mapping(bytes32=>bool) spent;
  function withdraw(uint256[8] calldata pf, bytes32 root, bytes32 nf, address recipient, uint256 amount) external {
    uint256[2] memory pub = [uint256(root), uint256(nf)];
    require(v.verifyProof(pf, pub), "bad"); require(!spent[nf]); spent[nf]=true;
    payable(recipient).transfer(amount);
  }
}""",
        """pragma solidity ^0.8.0;
interface IV { function verifyProof(uint256[8] calldata,uint256[4] calldata) external view returns(bool); }
contract Mixer { IV v; mapping(bytes32=>bool) spent;
  function withdraw(uint256[8] calldata pf, bytes32 root, bytes32 nf, address recipient, uint256 amount) external {
    uint256[4] memory pub = [uint256(root), uint256(nf), uint256(uint160(recipient)), amount];
    require(v.verifyProof(pf, pub), "bad"); require(!spent[nf]); spent[nf]=true;
    payable(recipient).transfer(amount);
  }
}""",
    ),
    (
        "verify_return_value_ignored",
        """pragma solidity ^0.8.0;
interface IVerifier { function verifyProof(bytes calldata,uint256[] calldata) external view returns(bool); }
contract Bridge { IVerifier verifier;
  function withdraw(bytes calldata proof, uint256[] calldata pub, address to, uint256 amount) external {
    verifier.verifyProof(proof, pub);
    payable(to).transfer(amount);
  }
}""",
        """pragma solidity ^0.8.0;
interface IVerifier { function verifyProof(bytes calldata,uint256[] calldata) external view returns(bool); }
contract Bridge { IVerifier verifier;
  function withdraw(bytes calldata proof, uint256[] calldata pub, address to, uint256 amount) external {
    require(verifier.verifyProof(proof, pub), "bad proof");
    payable(to).transfer(amount);
  }
}""",
    ),
    (
        "noop_stub_verifier_returns_true",
        """pragma solidity ^0.8.0;
contract StubVerifier {
  function verifyProof(bytes calldata, uint256[] calldata) external pure returns (bool) {
    return true;
  }
}""",
        """pragma solidity ^0.8.0;
contract Groth16Verifier {
  function verifyProof(bytes calldata proof, uint256[] calldata input) external view returns (bool) {
    bool ok; assembly { ok := staticcall(gas(), 0x08, add(proof,0x20), mload(proof), 0x00, 0x20) }
    require(ok, "pairing failed"); return ok;
  }
}""",
    ),
    (
        "verifier_staticcall_success_unchecked",
        """pragma solidity ^0.8.0;
contract Rollup { address verifier; bytes32 public dataRoot;
  function verifyAndUpdate(bytes memory proofData, bytes32 newRoot) internal {
    bool proof_verified; address v = verifier;
    assembly { proof_verified := staticcall(gas(), v, add(proofData,0x20), mload(proofData), 0x00, 0x00) }
    dataRoot = newRoot;
  }
}""",
        """pragma solidity ^0.8.0;
contract Rollup { address verifier; bytes32 public dataRoot;
  function verifyAndUpdate(bytes memory proofData, bytes32 newRoot) internal {
    bool proof_verified; address v = verifier;
    assembly { proof_verified := staticcall(gas(), v, add(proofData,0x20), mload(proofData), 0x00, 0x00) }
    require(proof_verified, "proof verification failed"); dataRoot = newRoot;
  }
}""",
    ),
    (
        "set_verifier_no_access_control",
        """pragma solidity ^0.8.0;
contract Rollup { address public verifier;
  function setVerifier(address _verifier) external { verifier = _verifier; }
}""",
        """pragma solidity ^0.8.0;
contract Rollup { address public verifier; address owner;
  modifier onlyOwner(){ require(msg.sender==owner); _; }
  function setVerifier(address _verifier) external onlyOwner { verifier = _verifier; }
}""",
    ),
    (
        "verifier_from_caller_supplied_source",
        """pragma solidity ^0.8.0;
interface IVerifier { function verify(bytes calldata,bytes32) external returns(bool); }
contract Settle {
  function settle(address verifier, bytes calldata proof, bytes32 root) external {
    require(IVerifier(verifier).verify(proof, root), "bad"); _credit(msg.sender, root);
  }
  function _credit(address,bytes32) internal {}
}""",
        """pragma solidity ^0.8.0;
interface IVerifier { function verify(bytes calldata,bytes32) external returns(bool); }
contract Settle { IVerifier public immutable verifier; constructor(IVerifier v){verifier=v;}
  function settle(bytes calldata proof, bytes32 root) external {
    require(verifier.verify(proof, root), "bad"); _credit(msg.sender, root);
  }
  function _credit(address,bytes32) internal {}
}""",
    ),
    (
        "nullifier_no_spent_check",
        """pragma solidity ^0.8.0;
contract Mixer { mapping(bytes32=>bool) public nullifierSpent;
  function withdraw(bytes calldata proof, bytes32 nullifier, address payable to) external {
    require(verifyProof(proof)); nullifierSpent[nullifier] = true; to.transfer(1 ether);
  }
  function verifyProof(bytes calldata p) internal returns(bool){return p.length>0;}
}""",
        """pragma solidity ^0.8.0;
contract Mixer { mapping(bytes32=>bool) public nullifierSpent;
  function withdraw(bytes calldata proof, bytes32 nullifier, address payable to) external {
    require(!nullifierSpent[nullifier], "spent"); require(verifyProof(proof));
    nullifierSpent[nullifier] = true; to.transfer(1 ether);
  }
  function verifyProof(bytes calldata p) internal returns(bool){return p.length>0;}
}""",
    ),
    (
        "nullifier_marked_after_transfer_cei",
        """pragma solidity ^0.8.0;
contract Mixer { mapping(bytes32=>bool) public nullifierSpent;
  function withdraw(bytes calldata proof, bytes32 nullifier, address payable to) external {
    require(!nullifierSpent[nullifier], "spent"); require(verifyProof(proof));
    (bool ok,) = to.call{value: 1 ether}(""); nullifierSpent[nullifier] = true;
  }
  function verifyProof(bytes calldata p) internal returns(bool){return p.length>0;}
}""",
        """pragma solidity ^0.8.0;
contract Mixer { mapping(bytes32=>bool) public nullifierSpent;
  function withdraw(bytes calldata proof, bytes32 nullifier, address payable to) external {
    require(!nullifierSpent[nullifier], "spent"); require(verifyProof(proof));
    nullifierSpent[nullifier] = true; (bool ok,) = to.call{value: 1 ether}("");
  }
  function verifyProof(bytes calldata p) internal returns(bool){return p.length>0;}
}""",
    ),
    (
        "nullifier_not_keyed_by_asset_or_recipient",
        """pragma solidity ^0.8.0;
contract Pool { mapping(bytes32=>bool) spent;
  function withdraw(bytes32 secret, uint256 amount, address payable recipient, bytes calldata proof) external {
    bytes32 nullifier = keccak256(abi.encodePacked(secret, amount));
    require(!spent[nullifier]); require(verifyProof(proof)); spent[nullifier]=true; recipient.transfer(amount);
  }
  function verifyProof(bytes calldata p) internal returns(bool){return p.length>0;}
}""",
        """pragma solidity ^0.8.0;
contract Pool { mapping(bytes32=>bool) spent;
  function withdraw(bytes32 secret, uint256 amount, address payable recipient, bytes calldata proof) external {
    bytes32 nullifier = keccak256(abi.encodePacked(secret, amount, recipient));
    require(!spent[nullifier]); require(verifyProof(proof)); spent[nullifier]=true; recipient.transfer(amount);
  }
  function verifyProof(bytes calldata p) internal returns(bool){return p.length>0;}
}""",
    ),
    (
        "unanchored_merkle_root_in_verification",
        """pragma solidity ^0.8.0;
contract Mixer {
  function withdraw(bytes32 root, bytes calldata proof, bytes32 nullifier) external {
    require(verifyProof(proof, root, nullifier), "bad"); payable(msg.sender).transfer(1 ether);
  }
  function verifyProof(bytes calldata p, bytes32 r, bytes32 n) internal returns (bool){ return p.length>0; }
}""",
        """pragma solidity ^0.8.0;
contract Mixer { mapping(bytes32 => bool) public roots;
  function withdraw(bytes32 root, bytes calldata proof, bytes32 nullifier) external {
    require(isKnownRoot(root), "unknown root"); require(verifyProof(proof, root, nullifier), "bad");
    payable(msg.sender).transfer(1 ether);
  }
  function isKnownRoot(bytes32 r) public view returns (bool){ return roots[r]; }
  function verifyProof(bytes calldata p, bytes32 r, bytes32 n) internal returns (bool){ return p.length>0; }
}""",
    ),
    (
        "commit_prove_decoupling_unproven_root",
        """pragma solidity ^0.8.0;
contract ZK { bytes32 public committedRoot;
  function commitBatch(bytes32 newRoot) external { committedRoot = newRoot; }
  function executeWithdraw(address payable to, uint256 amt, bytes32 root) external {
    require(root == committedRoot, "root"); to.transfer(amt);
  }
}""",
        """pragma solidity ^0.8.0;
contract ZK { bytes32 public committedRoot; mapping(bytes32=>bool) public verifiedBatches;
  function commitBatch(bytes32 newRoot) external { committedRoot = newRoot; }
  function proveBatch(bytes32 root, bytes calldata proof) external { require(verify(proof), "bad"); verifiedBatches[root] = true; }
  function executeWithdraw(address payable to, uint256 amt, bytes32 root) external {
    require(verifiedBatches[root], "unproven"); to.transfer(amt);
  }
  function verify(bytes calldata p) internal returns(bool){return p.length>0;}
}""",
    ),
    (
        "execute_batch_pubdata_hash_not_compared",
        """pragma solidity ^0.8.0;
contract Settle { mapping(address=>uint256) bal; struct Batch { bytes32 onChainOperationsHash; uint64 num; }
  function executeBatch(Batch memory batch, bytes memory pubData) external {
    uint256 i; bytes32 h;
    while (i + 52 <= pubData.length) { (address to, uint128 amt) = abi.decode(pubData, (address,uint128)); bal[to] += amt; h = keccak256(abi.encodePacked(h, to, amt)); i += 52; }
  }
}""",
        """pragma solidity ^0.8.0;
contract Settle { mapping(address=>uint256) bal; struct Batch { bytes32 onChainOperationsHash; uint64 num; }
  function executeBatch(Batch memory batch, bytes memory pubData) external {
    uint256 i; bytes32 h;
    while (i + 52 <= pubData.length) { (address to, uint128 amt) = abi.decode(pubData, (address,uint128)); bal[to] += amt; h = keccak256(abi.encodePacked(h, to, amt)); i += 52; }
    if (h != batch.onChainOperationsHash) revert();
  }
}""",
    ),
    (
        "public_input_missing_field_range_check",
        """pragma solidity ^0.8.0;
contract Verifier { uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  function verifyProof(uint256[8] calldata proof, uint256[3] calldata input) public view returns (bool) {
    return _pairing(proof, input);
  }
  function _pairing(uint256[8] calldata, uint256[3] calldata) internal view returns (bool) { return true; }
}""",
        """pragma solidity ^0.8.0;
contract Verifier { uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  function verifyProof(uint256[8] calldata proof, uint256[3] calldata input) public view returns (bool) {
    for (uint256 i = 0; i < input.length; i++) { require(input[i] < SNARK_SCALAR_FIELD, "input >= r"); }
    return _pairing(proof, input);
  }
  function _pairing(uint256[8] calldata, uint256[3] calldata) internal view returns (bool) { return true; }
}""",
    ),
    (
        "groth16_vk_degenerate_points",
        """pragma solidity ^0.8.0;
contract Verifier { struct G2Point { uint[2] X; uint[2] Y; } struct VK { G2Point gamma2; G2Point delta2; }
  function verifyingKey() internal pure returns (VK memory vk) {
    vk.gamma2 = G2Point([uint(0x1a),0x2b],[uint(0x3c),0x4d]);
    vk.delta2 = G2Point([uint(0x1a),0x2b],[uint(0x3c),0x4d]);
  }
  function verifyProof(uint[8] calldata proof, uint[2] calldata pub) external view returns(bool){ return proof[0]==pub[0] && vkUsed(); }
  function vkUsed() internal pure returns(bool){ VK memory k = verifyingKey(); return k.gamma2.X[0] != k.delta2.X[0]; }
}""",
        """pragma solidity ^0.8.0;
contract Verifier { struct G2Point { uint[2] X; uint[2] Y; } struct VK { G2Point gamma2; G2Point delta2; }
  function verifyingKey() internal pure returns (VK memory vk) {
    vk.gamma2 = G2Point([uint(0x1a),0x2b],[uint(0x3c),0x4d]);
    vk.delta2 = G2Point([uint(0x99),0x88],[uint(0x77),0x66]);
  }
  function verifyProof(uint[8] calldata proof, uint[2] calldata pub) external view returns(bool){ return proof[0]==pub[0] && vkUsed(); }
  function vkUsed() internal pure returns(bool){ VK memory k = verifyingKey(); return k.gamma2.X[0] != k.delta2.X[0]; }
}""",
    ),
    (
        "escape_hatch_missing_liveness_or_pause_gate",
        """pragma solidity ^0.8.0;
contract Rollup {
  function escapeHatch(address payable to, uint256 amount) external {
    to.transfer(amount);
  }
}""",
        """pragma solidity ^0.8.0;
contract Rollup { uint256 public lastInteraction; uint256 constant DELAY = 7 days; bool public frozen;
  function escapeHatch(address payable to, uint256 amount) external {
    require(block.timestamp > lastInteraction + DELAY || frozen, "not censored");
    to.transfer(amount);
  }
}""",
    ),
    (
        "public_input_packing_truncation_mismatch",
        """pragma solidity ^0.8.0;
interface IV { function verify(bytes calldata,uint256) external returns(bool); }
contract Exit { IV v;
  function exit(uint256 amount, address to, bytes calldata proof) external {
    uint256 commit = uint256(keccak256(abi.encodePacked(uint128(amount), to)));
    require(v.verify(proof, commit), "bad");
    payable(to).transfer(amount);
  }
}""",
        """pragma solidity ^0.8.0;
interface IV { function verify(bytes calldata,uint256) external returns(bool); }
contract Exit { IV v;
  function exit(uint256 amount, address to, bytes calldata proof) external {
    uint256 commit = uint256(keccak256(abi.encodePacked(amount, to)));
    require(v.verify(proof, commit), "bad");
    payable(to).transfer(amount);
  }
}""",
    ),
    (
        "settlement_count_not_bound_to_proof",
        """pragma solidity ^0.8.0;
contract Rollup { uint256 constant TXS_PER_ROLLUP = 28;
  function verify(bytes memory p, bytes32 h) internal returns(bool){ return p.length>0; }
  function decodeProof(bytes calldata d) internal pure returns(bytes memory, uint256, bytes32){ return (d, 1, bytes32(0)); }
  function processRollup(bytes calldata proofData, bytes calldata sigs) external {
    (bytes memory pd, uint256 numTxs, bytes32 publicInputsHash) = decodeProof(proofData);
    require(verify(pd, publicInputsHash), "bad proof");
    uint256 numFilledBlocks = numTxs / TXS_PER_ROLLUP;
    for (uint256 i = 0; i < numFilledBlocks; i++) { _settleBlock(pd, i); }
  }
  function _settleBlock(bytes memory, uint256) internal {}
}""",
        """pragma solidity ^0.8.0;
contract Rollup { uint256 constant TXS_PER_ROLLUP = 28;
  function verify(bytes memory p, bytes32 h) internal returns(bool){ return p.length>0; }
  function decodeProof(bytes calldata d) internal pure returns(bytes memory, uint256, bytes32){ return (d, 1, bytes32(0)); }
  function provenTxCount(bytes memory) internal pure returns(uint256){ return 1; }
  function processRollup(bytes calldata proofData, bytes calldata sigs) external {
    (bytes memory pd, uint256 numTxs, bytes32 publicInputsHash) = decodeProof(proofData);
    require(verify(pd, publicInputsHash), "bad proof");
    require(numTxs == provenTxCount(pd), "count mismatch");
    uint256 numFilledBlocks = numTxs / TXS_PER_ROLLUP;
    for (uint256 i = 0; i < numFilledBlocks; i++) { _settleBlock(pd, i); }
  }
  function _settleBlock(bytes memory, uint256) internal {}
}""",
    ),
    (
        "value_extracted_from_proofdata_unbound",
        """pragma solidity ^0.8.0;
contract Rollup {
  function verify(bytes memory p, bytes32 h) internal returns(bool){ return p.length>0; }
  function extractTotalTxFee(bytes memory) internal pure returns(uint256){ return 1; }
  function settle(bytes memory proofData, bytes32 publicInputsHash, address payable feeReceiver) internal {
    require(verify(proofData, publicInputsHash), "bad");
    uint256 txFee = extractTotalTxFee(proofData);
    feeReceiver.transfer(txFee);
  }
}""",
        """pragma solidity ^0.8.0;
contract Rollup {
  function verify(bytes memory p, bytes32 h) internal returns(bool){ return p.length>0; }
  function extractTotalTxFee(bytes memory) internal pure returns(uint256){ return 1; }
  function settle(bytes memory proofData, bytes32 publicInputsHash, address payable feeReceiver) internal {
    require(verify(proofData, publicInputsHash), "bad");
    require(sha256(proofData) == publicInputsHash, "unbound");
    uint256 txFee = extractTotalTxFee(proofData);
    feeReceiver.transfer(txFee);
  }
}""",
    ),
    (
        "circuit_soundness_out_of_scope_note",
        """pragma solidity ^0.8.0;
interface IV { function verifyProof(uint256[8] calldata, uint256[3] calldata) external view returns(bool); }
contract Pool { IV verifier; uint256 stateRoot; bytes32 commitment;
  function withdraw(uint256[8] calldata proof, uint256[3] calldata publicInput) external {
    require(verifier.verifyProof(proof, publicInput), "bad proof");
  }
}""",
        """pragma solidity ^0.8.0;
contract PlainToken { mapping(address=>uint256) bal;
  function transfer(address to, uint256 amt) external { bal[msg.sender]-=amt; bal[to]+=amt; }
}""",
    ),
]


@pytest.mark.parametrize("rule_id,positive,negative", FIXTURES, ids=[f[0] for f in FIXTURES])
def test_rule_fires_on_positive(rule_id, positive, negative):
    assert rule_id in _fired(positive), f"{rule_id} should fire on its vulnerable fixture"


@pytest.mark.parametrize("rule_id,positive,negative", FIXTURES, ids=[f[0] for f in FIXTURES])
def test_rule_silent_on_negative(rule_id, positive, negative):
    assert rule_id not in _fired(negative), f"{rule_id} false-positived on its safe fixture"


def test_plain_erc20_is_not_zk_gated():
    """A non-ZK contract must produce zero ZK findings (gate keeps noise out)."""
    src = "contract Token { mapping(address=>uint) b; function transfer(address t,uint a) external { b[msg.sender]-=a; b[t]+=a; } }"
    assert _fired(src) == set()


def test_aztec_escape_hatch_shape_surfaces_lead():
    """The real Aztec drain shape: verify() present and passing, yet the released
    amount is caller-supplied and unbound — must surface as the forced-exit lead,
    not be cleared by the presence of verify()."""
    src = """pragma solidity ^0.8.0;
contract RollupProcessor {
  function verify(bytes calldata p) internal returns(bool){ return p.length > 0; }
  function escapeHatch(bytes calldata proofData, bytes calldata signatures, uint256 publicOutput, address payable to) external {
    require(verify(proofData), "invalid proof");
    (bool ok,) = to.call{value: publicOutput}(""); require(ok);
  }
}"""
    fired = _fired(src)
    assert "forced_exit_released_value_unbound_to_proof" in fired


def test_aztec_connect_numtxs_boundary_surfaces_lead():
    """The real Aztec Connect $2.19M shape: numTxs decoded from calldata bounds the
    settlement loop while the proof commits a fixed range, with no
    require(numTxs == provenCount). Must surface as the settlement-boundary lead."""
    src = """pragma solidity ^0.8.0;
contract RollupProcessorV2 {
  uint256 constant TXS_PER_ROLLUP = 28;
  function verifyProofData(bytes memory p, bytes32 h) internal returns(bool){ return p.length>0; }
  function decodeProof(bytes calldata d) internal pure returns(bytes memory, uint256, bytes32){ return (d, 1, bytes32(0)); }
  function processRollup(bytes calldata, bytes calldata _signatures) external {
    (bytes memory proofData, uint256 numTxs, bytes32 publicInputsHash) = decodeProof(msg.data);
    require(verifyProofData(proofData, publicInputsHash), "PROOF_VERIFICATION_FAILED");
    uint256 numFilledBlocks = numTxs / TXS_PER_ROLLUP;
    for (uint256 i = 0; i < numFilledBlocks; i++) { _processRollupProof(proofData, i); }
  }
  function _processRollupProof(bytes memory, uint256) internal {}
}"""
    assert "settlement_count_not_bound_to_proof" in _fired(src)
