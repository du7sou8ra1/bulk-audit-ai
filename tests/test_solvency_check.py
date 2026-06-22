"""Missing post-mutation solvency/health check (v0.5) -- Euler donateToReserves class."""
from pathlib import Path
from backend.detectors.base import TargetContext
from backend.detectors.solvency_check import SolvencyCheckDetector


def _ctx(src):
    return TargetContext(address="0xabc", chain="ethereum", profile="defi-deep",
                         onchain=None, proxy_info=None, workspace=Path("."),
                         contract_name="T", source_files={"T.sol": src})


def _solvency(src):
    return [f for f in SolvencyCheckDetector().run(_ctx(src)) if f.evidence.get("bug_class") == "solvency"]


EULER = """contract EToken {
  mapping(address => uint) balances;
  uint totalReserves;
  function checkLiquidity(address account) internal view { require(account != address(0)); }
  function withdraw(uint amt) external { balances[msg.sender] = balances[msg.sender] - amt; checkLiquidity(msg.sender); }
  function borrow(uint amt) external { balances[msg.sender] = balances[msg.sender] + amt; checkLiquidity(msg.sender); }
  function donateToReserves(uint amt) external { balances[msg.sender] = balances[msg.sender] - amt; totalReserves = totalReserves + amt; }
}"""

SAFE_SYMMETRIC = """contract Safe {
  mapping(address => uint) balances;
  function checkLiquidity(address a) internal view { require(a != address(0)); }
  function withdraw(uint amt) external { balances[msg.sender] = balances[msg.sender] - amt; checkLiquidity(msg.sender); }
  function repay(uint amt) external { balances[msg.sender] = balances[msg.sender] + amt; checkLiquidity(msg.sender); }
}"""

PLAIN_TOKEN = """contract Token {
  mapping(address => uint) balances;
  function transfer(address to, uint amt) external { balances[msg.sender] = balances[msg.sender] - amt; balances[to] = balances[to] + amt; }
}"""


def test_euler_donate_to_reserves_flagged():
    fs = _solvency(EULER)
    assert fs and any("donateToReserves" in f.affected_functions for f in fs)
    flagged = {fn for f in fs for fn in f.affected_functions}
    assert "withdraw" not in flagged and "borrow" not in flagged


def test_symmetric_all_checked_not_flagged():
    assert not _solvency(SAFE_SYMMETRIC)


def test_plain_token_no_solvency_concept_not_flagged():
    assert not _solvency(PLAIN_TOKEN)
