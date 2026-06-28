from pathlib import Path


def test_weird_hunt_semgrep_rules_are_registered():
    text = Path("backend/semgrep_rules/solidity.yml").read_text(encoding="utf-8")
    for rule_id in {
        "solidity-transferfrom-no-balance-delta",
        "solidity-merkle-claim-weak-binding",
        "solidity-bitmap-claim-shift-without-word-index",
        "solidity-bridge-message-key",
        "solidity-chainlink-latest-round-data",
        "solidity-address-this-balance-accounting",
        "solidity-payable-multicall-delegatecall",
        "solidity-trycatch-swallowed-finalization",
        "solidity-batch-loop-value-mutation",
        "solidity-create2-address-only-trust",
    }:
        assert f"id: {rule_id}" in text
