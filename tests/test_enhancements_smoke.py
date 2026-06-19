"""Smoke tests for the v0.3 enhancement modules (gaps #1-#8).

These exercise the NON-LLM logic only (call graph, coverage, scoring refutation
cap, library fingerprinting). LLM/network paths are not invoked.
Run: pytest tests/test_enhancements_smoke.py -q
"""
from pathlib import Path

from backend.core.callgraph import CallGraph
from backend.core import coverage as coverage_mod
from backend.core.scoring import score_finding
from backend.core.source_fetcher import is_known_library_file, project_source_files
from backend.detectors.base import FindingCandidate, TargetContext

_VAULT = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public pendingBalances;
    uint256 public totalPending;
    function _credit(address to, uint256 amt) internal {
        pendingBalances[to] += amt;
        totalPending += amt;
    }
    function withdraw(address to, uint256 amt) external {
        require(amt <= pendingBalances[to], "too much");
        _credit(to, 0);
        (bool ok,) = to.call{value: amt}("");
        require(ok);
    }
    function totalAssets() public view returns (uint256) { return totalPending; }
}
"""

_ZK = """
pragma solidity ^0.8.0;
contract Rollup {
    bytes32 public stateRoot;
    mapping(uint=>uint) pendingBalances;
    function executeBatches(bytes calldata pubdata) external {
        // no proof verification, no hash binding -> should be flagged
        increaseBalanceToWithdraw(msg.sender, 0, 100);
    }
    function increaseBalanceToWithdraw(address a, uint16 i, uint128 v) internal {}
    function verifyProof(bytes calldata p) external returns (bool) { return true; }
}
"""


def _ctx(src: str, addr="0xabc") -> TargetContext:
    return TargetContext(
        address=addr, chain="ethereum", profile="deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="Vault", source_files={"Vault.sol": src},
    )


def test_callgraph_builds_edges_and_slices():
    cg = CallGraph.build({"Vault.sol": _VAULT})
    assert "withdraw" in cg.fns and "_credit" in cg.fns
    # withdraw calls _credit
    assert "_credit" in cg.fns["withdraw"].calls
    # slice for withdraw must include its callee body
    sl = cg.slice_for("withdraw")
    assert "_credit" in sl and "pendingBalances" in sl
    # state-changing externals exclude the view totalAssets
    names = {n.name for n in cg.state_changing_externals()}
    assert "withdraw" in names and "totalAssets" not in names


def test_coverage_flags_zk_circuit_out_of_scope():
    ctx = _ctx(_ZK)
    cov = coverage_mod.build_coverage(
        ctx, detectors_run=["zk_verifier"], tool_statuses={"slither": "ok"},
        candidate_count=0, source_verified=True, reasoner_meta={},
    )
    assert any("circuit" in s.lower() for s in cov["out_of_tool_scope"])
    assert "honest_summary" in cov and cov["state_changing_externals"] >= 1


def test_scoring_caps_refuted_finding():
    cand = FindingCandidate(
        detector="invariant_reasoner", title="x", description="y",
        impact_score=9.0, confidence_score=8.0, severity_candidate="critical",
        evidence={"refuted": True, "refutation": {"refutation": "gated by require"}},
    )
    res = score_finding(cand, [])
    assert res.confidence_score <= 2.0  # hard-capped -> cannot be CONFIRMED_CRITICAL
    assert res.classification != "CONFIRMED_CRITICAL"


def test_scoring_rewards_survivor():
    cand = FindingCandidate(
        detector="invariant_reasoner", title="x", description="y",
        impact_score=9.0, confidence_score=6.0, severity_candidate="critical",
        evidence={"refutation": {"attempted": True, "is_real": True}, "unprivileged": True},
    )
    res = score_finding(cand, [])
    assert res.confidence_score >= 6.0


def test_library_fingerprinting():
    assert is_known_library_file("lib/openzeppelin-contracts/token/ERC20.sol")
    assert not is_known_library_file("src/MyVault.sol")
    files = {"@openzeppelin/contracts/Ownable.sol": "x", "src/Core.sol": "y"}
    assert project_source_files(files) == {"src/Core.sol": "y"}
