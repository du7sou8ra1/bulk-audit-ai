"""Critical-class vector upgrades: delegatecall-to-attacker-target (Furucombo),
UUPS empty _authorizeUpgrade (Wormhole), and Nomad default-root acceptance ($190M).
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_proxy_bridge_upgrades.py -q
"""
from pathlib import Path

from backend.detectors.access_control import AccessControlDetector
from backend.detectors.base import TargetContext
from backend.detectors.bridge_accounting import BridgeAccountingDetector
from backend.detectors.delegatecall import DelegatecallDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="ultra-deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _titles(detector, src: str) -> str:
    return " || ".join(f.title.lower() for f in detector.run(_ctx(src)))


def _rule_ids(detector, src: str) -> set[str]:
    return {f.evidence.get("rule_id") for f in detector.run(_ctx(src))}


# ---- PRX-DELEGATECALL (Furucombo) ----
def test_delegatecall_attacker_target_fires():
    src = ("contract FurucomboProxy { function exec(address _to, bytes memory data) external payable { "
           "assembly { let s := delegatecall(gas(), _to, add(data,0x20), mload(data), 0, 0) "
           "if eq(s,0){revert(0,0)} } } }")
    assert "attacker-settable target" in _titles(DelegatecallDetector(), src)


def test_delegatecall_immutable_target_silent():
    src = ("contract SafeProxy { address immutable impl; constructor(address i){ impl=i; } "
           "function run() external { impl.delegatecall(msg.data); } }")
    assert "attacker-settable target" not in _titles(DelegatecallDetector(), src)


# ---- AC-UUPS-AUTHORIZE (Wormhole) ----
def test_uups_empty_authorize_fires():
    src = ("contract Vault is UUPSUpgradeable { "
           "function _authorizeUpgrade(address newImplementation) internal override {} }")
    assert "uups_authorize_upgrade_empty" in _rule_ids(AccessControlDetector(), src)


def test_uups_guarded_authorize_silent():
    src = ("contract Vault is UUPSUpgradeable { address owner; "
           "function _authorizeUpgrade(address newImplementation) internal override "
           "{ require(msg.sender == owner, 'not owner'); } }")
    assert "uups_authorize_upgrade_empty" not in _rule_ids(AccessControlDetector(), src)


# ---- BRIDGE-ROOT-ZERO (Nomad) ----
def test_nomad_default_root_acceptance_fires():
    src = """contract CrossChainBridge {
  mapping(bytes32=>bool) acceptableRoot;
  function process(bytes32 _root, bytes calldata _msg, bytes32[32] calldata _proof) external returns(bool){
    require(acceptableRoot[_root], "!proven"); _dispatch(_msg); return true;
  }
  function _dispatch(bytes calldata d) internal {}
}"""
    assert "bridge_root_default_acceptance" in _rule_ids(BridgeAccountingDetector(), src)


def test_nomad_with_zero_rejection_silent():
    src = """contract CrossChainBridge {
  enum Status { None, Proven }
  mapping(bytes32=>Status) rootStatus;
  function process(bytes32 _root, bytes calldata _msg, bytes32[32] calldata _proof) external returns(bool){
    require(_root != bytes32(0), "zero root");
    require(rootStatus[_root] == Status.Proven, "!proven");
    _dispatch(_msg); return true;
  }
  function _dispatch(bytes calldata d) internal {}
}"""
    assert "bridge_root_default_acceptance" not in _rule_ids(BridgeAccountingDetector(), src)
