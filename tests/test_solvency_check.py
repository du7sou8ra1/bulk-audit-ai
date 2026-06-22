"""Missing post-mutation solvency/health check (v0.5) -- the Euler donateToReserves class.

Pure source analysis -- no LLM/network/RPC.
"""
from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.solvency_check import SolvencyCheckDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="defi-deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _solvency(src):
    return [f for f in SolvencyCheckDetector().run(_ctx(src))
            if f.evidence.get("bug_class") == "solvency"]


# Euler shape: withdraw/borrow enforce checkLiquidity; donateToReserves does not.
EULER = """contract EToken {
  mapping(address => uint) balances;
  uint totalReserves;
  function checkLiquidity(address account) internal view { require(account != address(0)); }
  function withdraw(uint amt) external {
    balances[msg.sender] = balances[msg.sender] - amt;
    checkLiquidity(msg.sender);
  }
  function borrow(uint amt) external {
    balances[msg.sender] = balances[msg.sender] + amt;
    checkLiquidity(msg.sender);
  }
  function donateToReserves(uint amt) external {
    balances[msg.sender] = balances[msg.sender] - amt;
    totalReserves = totalReserves + amt;
  }
}"""

# Symmetric: every mutator checks -> nothing to flag.
SAFE_SYMMETRIC = """contract Safe {
  mapping(address => uint) balances;
  function checkLiquidity(address a) internal view { require(a != address(0)); }
  function withdraw(uint amt) external { balances[msg.sender] = balances[msg.sender] - amt; checkLiquidity(msg.sender); }
  function repay(uint amt) external { balances[msg.sender] = balances[msg.sender] + amt; checkLiquidity(msg.sender); }
}"""

# No solvency concept at all (plain token) -> never fires.
PLAIN_TOKEN = """contract Token {
  mapping(address => uint) balances;
  function transfer(address to, uint amt) external {
    balances[msg.sender] = balances[msg.sender] - amt;
    balances[to] = balances[to] + amt;
  }
}"""


def test_euler_donate_to_reserves_flagged():
    findings = _solvency(EULER)
    assert findings, "asymmetric missing-liquidity-check path should be flagged"
    assert any("donateToReserves" in f.affected_functions for f in findings)
    # and we must NOT flag the paths that DO check
    flagged = {fn for f in findings for fn in f.affected_functions}
    assert "withdraw" not in flagged and "borrow" not in flagged


def test_symmetric_all_checked_not_flagged():
    assert not _solvency(SAFE_SYMMETRIC)


def test_plain_token_no_solvency_concept_not_flagged():
    assert not _solvency(PLAIN_TOKEN)
