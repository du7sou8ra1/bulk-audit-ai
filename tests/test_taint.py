from backend.core.semantic_index import build_semantic_index
from backend.core.taint import analyze_taint, external_entrypoints_reaching, flows_to_sink


SOURCE = """
pragma solidity ^0.8.20;

interface IERC20 { function safeTransfer(address to, uint256 amount) external; }

contract TaintVault {
    IERC20 public token;
    mapping(bytes32 => bool) public processed;
    mapping(address => uint256) public rewardDebt;

    function claim(bytes calldata payload) external {
        (address recipient, uint256 amount, bytes32 id) = abi.decode(payload, (address, uint256, bytes32));
        _pay(recipient, amount, id);
    }

    function _pay(address recipient, uint256 amount, bytes32 id) internal {
        token.safeTransfer(recipient, amount);
        processed[id] = true;
        rewardDebt[recipient] = amount;
    }

    function adminSweep(address treasury, uint256 amount) external {
        token.safeTransfer(treasury, amount);
    }
}
"""


def test_taint_follows_calldata_into_internal_value_sink():
    facts = build_semantic_index({"TaintVault.sol": SOURCE})
    flows = flows_to_sink(facts, source="calldata", sink="value_transfer")

    claim_flows = [f for f in flows if f.entrypoint == "claim" and f.function == "_pay"]
    assert claim_flows
    assert any(f.cross_function for f in claim_flows)
    assert any(f.path == ["claim", "_pay"] for f in claim_flows)
    assert {"recipient", "amount", "cross_function_args"}.intersection({f.source for f in claim_flows})


def test_taint_reports_replay_and_accounting_writes():
    facts = build_semantic_index({"TaintVault.sol": SOURCE})
    report = analyze_taint(facts)
    replay = [f for f in report.flows if f.entrypoint == "claim" and f.sink_kind == "replay_marker"]
    accounting = [f for f in report.flows if f.entrypoint == "claim" and f.sink_kind == "accounting_write"]

    assert replay
    assert accounting
    assert "claim" in external_entrypoints_reaching(facts, "_pay")


def test_taint_filter_respects_confidence_threshold():
    facts = build_semantic_index({"TaintVault.sol": SOURCE})
    assert flows_to_sink(facts, source="calldata", sink="value_transfer", min_confidence=0.95) == []

