"""Smoke tests for the v0.4 attack-class detectors (2026 incident coverage).

Each test feeds a minimal VULNERABLE snippet and asserts the matching detector
fires, and (where cheap) a SAFE snippet that should not. Pure source analysis —
no LLM/network/RPC.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_attack_class_detectors.py -q
"""
from pathlib import Path

from backend.detectors.access_control import AccessControlDetector
from backend.detectors.arithmetic_logic import ArithmeticLogicDetector
from backend.detectors.base import TargetContext
from backend.detectors.oracle_manipulation import OracleManipulationDetector
from backend.detectors.reentrancy import ReentrancyDetector
from backend.detectors.signature_replay import SignatureReplayDetector
from backend.detectors.time_logic import TimeLogicDetector
from backend.detectors.token_logic import TokenLogicDetector
from backend.detectors.zk_verifier import ZkVerifierDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="defi-deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _titles(findings):
    return " || ".join(f.title.lower() for f in findings)


def test_oracle_spot_price():
    src = """contract P { uint reward;
      function price() public view returns (uint) {
        (uint160 sp,,,,,,) = pool.slot0(); return uint(sp) * reward; } }"""
    f = OracleManipulationDetector().run(_ctx(src))
    assert any(c.evidence.get("bug_class") == "oracle" for c in f)
    assert "spot" in _titles(f)


def test_access_control_missing_modifier():
    bad = "contract C { address owner; function setOwner(address o) external { owner = o; } }"
    good = "contract C { address owner; function setOwner(address o) external onlyOwner { owner = o; } }"
    assert any("no access control" in c.title.lower() for c in AccessControlDetector().run(_ctx(bad)))
    assert not any("no access control" in c.title.lower() for c in AccessControlDetector().run(_ctx(good)))


def test_arithmetic_double_mint_and_unchecked():
    src = """contract M { mapping(bytes32=>bool) used;
      function claimReward(uint a, uint b, address to) external {
        unchecked { uint c = a + b; } _mint(to, c); } }"""
    f = ArithmeticLogicDetector().run(_ctx(src))
    classes = {c.evidence.get("bug_class") for c in f}
    assert "double_mint" in classes or "math" in classes


def test_reentrancy_call_before_write():
    src = """contract V { mapping(address=>uint) balances;
      function withdraw() external {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0; } }"""
    f = ReentrancyDetector().run(_ctx(src))
    assert any(c.evidence.get("bug_class") == "reentrancy" for c in f)


def test_signature_replay_no_nonce():
    src = """contract S { function exec(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(h, v, r, s); doThing(signer); } }"""
    f = SignatureReplayDetector().run(_ctx(src))
    assert any(c.evidence.get("bug_class") == "signature" for c in f)


def test_time_logic_backdate():
    src = """contract D { uint unlockTime;
      function setUnlockTime(uint t) external { unlockTime = t; } }"""
    f = TimeLogicDetector().run(_ctx(src))
    assert any("monotonicity" in c.title.lower() for c in f)


def test_token_unchecked_transfer():
    src = """contract Tk { function pay(address to, uint amt) external {
        token.transfer(to, amt); } }"""
    f = TokenLogicDetector().run(_ctx(src))
    assert any("unchecked" in c.title.lower() for c in f)


def test_groth16_gamma_eq_delta():
    src = """contract Verifier {
      // proof verification with a broken verifying key (commitment, proof, verifyProof)
      uint256 constant gammax1 = 0x111; uint256 constant gammay1 = 0x222;
      uint256 constant deltax1 = 0x111; uint256 constant deltay1 = 0x222;
      function verifyProof(bytes calldata proof) external returns (bool) { return true; }
      bytes32 commitment; }"""
    f = ZkVerifierDetector().run(_ctx(src))
    assert any("gamma == delta" in c.title.lower() for c in f)
    assert any(c.impact_score >= 9.5 for c in f if "gamma" in c.title.lower())
