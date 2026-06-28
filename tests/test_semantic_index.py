from backend.core.semantic_index import build_semantic_index, reachable_functions


SOURCE = """
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
}

contract SemanticVault {
    IERC20 public token;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public processed;
    event Paid(address indexed to, uint256 amount);

    modifier onlyKeeper() { require(msg.sender == keeper, "keeper"); _; }
    address public keeper;

    function deposit(uint256 amount) external payable {
        require(amount > 0, "amount");
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    function claim(bytes calldata payload) external {
        (address recipient, uint256 amount, bytes32 id) = abi.decode(payload, (address, uint256, bytes32));
        _pay(recipient, amount, id);
    }

    function _pay(address recipient, uint256 amount, bytes32 id) internal {
        require(!processed[id], "used");
        token.safeTransfer(recipient, amount);
        processed[id] = true;
        emit Paid(recipient, amount);
    }

    function sweep(address to, uint256 amount) external onlyKeeper {
        token.safeTransfer(to, amount);
    }
}
"""


def test_semantic_index_extracts_function_facts_and_state():
    facts = build_semantic_index({"SemanticVault.sol": SOURCE})

    assert set(facts.entrypoints) >= {"deposit", "claim", "sweep"}
    assert "balances" in facts.mappings
    assert facts.mappings["processed"]["key_type"] == "bytes32"

    deposit = facts.get_function("deposit")
    assert deposit is not None
    assert deposit.visibility == "external"
    assert deposit.mutability == "payable"
    assert deposit.params[0]["name"] == "amount"
    assert any("require" in guard for guard in deposit.guards)
    assert "balances" in deposit.writes
    assert any(sink["sink"] == "transferFrom" for sink in deposit.value_sinks)

    claim = facts.get_function("claim")
    pay = facts.get_function("_pay")
    assert claim is not None and pay is not None
    assert claim.calls == {"_pay"}
    assert {"recipient", "amount", "id"}.issubset(claim.decoded_fields)
    assert "claim" in facts.external_entrypoints_reaching("_pay")
    assert reachable_functions(facts, "claim") == {"claim", "_pay"}
    assert "processed" in pay.writes
    assert any(sink["sink"] == "safeTransfer" and sink["before_state_update"] for sink in pay.value_sinks)
    assert "Paid" in pay.events


def test_semantic_index_marks_custom_modifier_guards():
    facts = build_semantic_index({"SemanticVault.sol": SOURCE})
    sweep = facts.get_function("sweep")
    assert sweep is not None
    assert "onlyKeeper" in sweep.modifiers
    assert "onlyKeeper" in sweep.guards

