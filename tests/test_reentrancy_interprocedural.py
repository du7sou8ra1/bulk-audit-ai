"""Interprocedural / cross-function reentrancy (v0.5) -- Rari/Fuse CEther class."""
from pathlib import Path
from backend.detectors.base import TargetContext
from backend.detectors.reentrancy import ReentrancyDetector


def _ctx(src):
    return TargetContext(address="0xabc", chain="ethereum", profile="defi-deep",
                         onchain=None, proxy_info=None, workspace=Path("."),
                         contract_name="T", source_files={"T.sol": src})


def _reentrancy(src):
    return [f for f in ReentrancyDetector().run(_ctx(src)) if f.evidence.get("bug_class") == "reentrancy"]


RARI = """contract Fuse {
  mapping(address => uint) accountBorrows;
  uint totalBorrows;
  function doTransferOut(address payable to, uint amt) internal {
    (bool ok, ) = to.call{value: amt}("");
    require(ok, "send");
  }
  function borrowFresh(address payable borrower, uint amt) internal {
    doTransferOut(borrower, amt);
    accountBorrows[borrower] = accountBorrows[borrower] + amt;
    totalBorrows = totalBorrows + amt;
  }
}"""

SAFE_CEI = """contract Safe {
  mapping(address => uint) balances;
  function doTransferOut(address payable to, uint amt) internal { to.transfer(amt); }
  function withdraw(uint amt) external {
    balances[msg.sender] = balances[msg.sender] - amt;
    doTransferOut(payable(msg.sender), amt);
  }
}"""

SAFE_NOWRITE = """contract Safe2 {
  function doTransferOut(address payable to, uint amt) internal { to.transfer(amt); }
  function pay(address payable to, uint amt) internal { uint x = amt; doTransferOut(to, amt); }
}"""


def test_interprocedural_cei_detected():
    fs = _reentrancy(RARI)
    assert fs, "interprocedural CEI (Rari/Fuse) should be flagged"
    inter = [f for f in fs if f.evidence.get("interprocedural")]
    assert inter and any("borrowFresh" in f.affected_functions for f in inter)


def test_cei_correct_not_flagged():
    assert not _reentrancy(SAFE_CEI)


def test_helper_send_without_state_write_not_flagged():
    assert not _reentrancy(SAFE_NOWRITE)


def test_direct_cei_still_detected():
    src = """contract V { mapping(address=>uint) balances;
      function withdraw() external {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0; } }"""
    assert _reentrancy(src)
