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
        "solidity-live-balance-reward-without-checkpoint",
        "solidity-whitelist-claim-no-replay-marker",
        "solidity-redemption-math-after-supply-burn",
        "solidity-erc4626-dual-asset-redeem-double-count",
        "solidity-amm-pair-burn-sync-reserve-desync",
    }:
        assert f"id: {rule_id}" in text
