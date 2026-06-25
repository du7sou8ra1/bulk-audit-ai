from pathlib import Path

from backend.core.fuzzing import (
    generate_foundry_starter_suite,
    inspect_fuzz_readiness,
    infer_surfaces,
)
from backend.detectors.base import TargetContext


def _ctx(abi=None, source="contract Vault {}") -> TargetContext:
    return TargetContext(
        address="0x1111111111111111111111111111111111111111",
        chain="ethereum",
        profile="ultra-deep-v2",
        onchain=None,
        proxy_info=None,
        workspace=Path("."),
        contract_name="Vault",
        source_files={"Vault.sol": source},
        abi=abi or [],
        bytecode="0x",
    )


def test_inspect_fuzz_readiness_detects_foundry_and_invariants(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    (test_dir / "Vault.t.sol").write_text(
        """
        contract VaultTest {
          function testFuzz_deposit(uint256 amount) public {}
          function invariant_assets_cover_shares() public {}
        }
        """,
        encoding="utf-8",
    )

    res = inspect_fuzz_readiness(
        tmp_path,
        {"Vault.sol": "contract Vault { function deposit(uint256 assets) external {} function withdraw(uint256 shares) external {} }"},
    )

    assert res["foundry_project"] is True
    assert res["foundry_fuzz_files"] == ["test/Vault.t.sol"]
    assert res["foundry_invariant_files"] == ["test/Vault.t.sol"]
    assert "vault/share accounting" in res["surfaces"]


def test_infer_surfaces_rewards_and_bridge():
    text = """
    contract RewardsBridge {
      function claimReward() external {}
      function processMessage(bytes32 root, bytes calldata proof) external {}
    }
    """
    surfaces = infer_surfaces(text)
    assert "rewards/checkpoints" in surfaces
    assert "bridge/proof replay" in surfaces


def test_generate_foundry_starter_suite_from_abi(tmp_path):
    abi = [
        {
            "type": "function",
            "name": "deposit",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "assets", "type": "uint256"}],
        },
        {
            "type": "function",
            "name": "claimReward",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "account", "type": "address"}, {"name": "proof", "type": "bytes32"}],
        },
        {
            "type": "function",
            "name": "bulkDeposit",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "amounts", "type": "uint256[]"}],
        },
        {
            "type": "function",
            "name": "totalAssets",
            "stateMutability": "view",
            "inputs": [],
        },
    ]
    ctx = _ctx(
        abi=abi,
        source="contract Vault { function deposit(uint256 assets) external {} function claimReward(address account, bytes32 proof) external {} }",
    )

    suite = generate_foundry_starter_suite(ctx, tmp_path / "generated")
    test_text = suite.test_path.read_text(encoding="utf-8")
    plan_text = suite.plan_path.read_text(encoding="utf-8")

    assert suite.fuzz_tests == 2
    assert "testFuzz_deposit_" in test_text
    assert 'keccak256(bytes("deposit(uint256)"))' in test_text
    assert "testFuzz_claimReward_" in test_text
    assert "bulkDeposit(uint256[])" in suite.skipped_functions
    assert "vault/share accounting" in plan_text
    assert "Generated ABI fuzz tests: 2" in plan_text

