from pathlib import Path

from backend.core.fuzzing import (
    generate_detector_invariant_suite,
    generate_foundry_starter_suite,
    inspect_fuzz_readiness,
    infer_surfaces,
    run_detector_invariant_generation,
)
from backend.detectors.base import FindingCandidate, TargetContext


def _ctx(abi=None, source="contract Vault {}", address="0x1111111111111111111111111111111111111111") -> TargetContext:
    return TargetContext(
        address=address,
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
    assert Path(suite.fuzzer_artifacts["echidna_harness"]).exists()
    assert Path(suite.fuzzer_artifacts["echidna_config"]).exists()
    assert Path(suite.fuzzer_artifacts["medusa_config"]).exists()
    assert "BulkAuditEchidnaProperties" in Path(suite.fuzzer_artifacts["echidna_harness"]).read_text(encoding="utf-8")
    assert "--foundry-compile-all" in Path(suite.fuzzer_artifacts["echidna_config"]).read_text(encoding="utf-8")
    assert "BulkAuditEchidnaProperties" in Path(suite.fuzzer_artifacts["medusa_config"]).read_text(encoding="utf-8")


def test_generate_detector_invariant_suite_from_high_signal_findings(tmp_path):
    abi = [
        {
            "type": "function",
            "name": "safeTransferFrom",
            "stateMutability": "nonpayable",
            "inputs": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "id", "type": "uint256"},
                {"name": "amount", "type": "uint256"},
                {"name": "data", "type": "bytes"},
            ],
        },
        {
            "type": "function",
            "name": "deposit",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "assets", "type": "uint256"}],
        },
        {
            "type": "function",
            "name": "withdraw",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "shares", "type": "uint256"}],
        },
        {
            "type": "function",
            "name": "asset",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": "address"}],
        },
        {
            "type": "function",
            "name": "totalAssets",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": "uint256"}],
        },
    ]
    ctx = _ctx(
        abi=abi,
        source="""
        contract RoyaltiesVault {
          function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external {}
          function deposit(uint256 assets) external {}
          function withdraw(uint256 shares) external {}
          function totalAssets() external view returns (uint256) {}
        }
        """,
    )
    findings = [
        FindingCandidate(
            detector="zero_transfer_reward_checkpoint",
            title="Zero-value transfers stack reward records",
            description="Repeated zero-value transfers append settlement checkpoints and multiply claims.",
            impact_score=8.8,
            confidence_score=7.0,
            severity_candidate="high",
            evidence={"rule_id": "zero_transfer_stacks_reward_records"},
            affected_functions=["safeTransferFrom"],
        ),
        FindingCandidate(
            detector="lending_exchange_rate_donation",
            title="Direct donation inflates share price",
            description="Reserve donation can distort exchange rate before victim deposit.",
            impact_score=8.4,
            confidence_score=6.4,
            severity_candidate="high",
            evidence={"rule_id": "share_price_donation_inflation"},
            affected_functions=["deposit"],
        ),
    ]

    suite = generate_detector_invariant_suite(ctx, findings, tmp_path / "detector")
    test_text = suite.test_path.read_text(encoding="utf-8")
    plan_text = suite.plan_path.read_text(encoding="utf-8")

    assert suite.fuzz_tests == 2
    assert suite.stateful_tests == 2
    assert suite.asset_probes == 1
    assert suite.accounting_probes == 1
    assert "BulkAuditDetectorInvariants" in test_text
    assert "AUTO-GENERATED by BulkAuditAI Elite fuzzing phase 4" in test_text
    assert "interface Vm" in test_text
    assert "interface IERC20Like" in test_text
    assert "function setUp() public" in test_text
    assert "BULKAUDIT_FORK" in test_text
    assert "createSelectFork" in test_text
    assert "ATTACKER" in test_text
    assert "testFuzz_detector_zero_transfer_reward_checkpoint_0" in test_text
    assert "testFuzz_stateful_detector_zero_transfer_reward_checkpoint_0" in test_text
    assert "safeTransferFrom(address,address,uint256,uint256,bytes)" in test_text
    assert "uint256(0)" in test_text
    assert "testFuzz_detector_donation_share_inflation_1" in test_text
    assert "_statefulRepeatNoProfit" in test_text
    assert "_assertNoEthProfit" in test_text
    assert "_assertNoAssetProfit" in test_text
    assert "_assetSnapshot" in test_text
    assert "_accountingSnapshot" in test_text
    assert "_assertAccountingStable" in test_text
    assert 'keccak256(bytes("asset()"))' in test_text
    assert 'keccak256(bytes("totalAssets()"))' in test_text
    assert "DetectorProbe" in test_text
    assert "Fork Hydration" in plan_text
    assert "Inferred Asset Getters" in plan_text
    assert "Inferred Accounting Getters" in plan_text
    assert "`asset()`" in plan_text
    assert "`totalAssets()`" in plan_text
    assert "Zero-value transfers and empty settlement updates" in plan_text
    assert "honest user assets are conserved" in plan_text
    assert "Elite phase 5" in plan_text
    assert Path(suite.fuzzer_artifacts["echidna_harness"]).exists()
    assert "BulkAuditDetectorInvariants" in Path(suite.fuzzer_artifacts["fuzzer_readme"]).read_text(encoding="utf-8")


def test_detector_invariant_generation_skips_low_signal_findings(tmp_path):
    ctx = _ctx()
    low = FindingCandidate(
        detector="style_note",
        title="Informational note",
        description="No exploit path.",
        impact_score=2.0,
        confidence_score=5.0,
        severity_candidate="info",
        evidence={"informational": True},
    )

    res = run_detector_invariant_generation(ctx, [low], tmp_path / "detector")

    assert res.status == "skipped"
    assert "no high-signal" in res.summary
    assert res.json_output_path


def test_detector_invariant_suite_checksums_addresses_and_maps_zk_to_bridge(tmp_path):
    ctx = _ctx(
        abi=[],
        address="0xff1f2b4adb9df6fc8eafecdcbf96a2b351680455",
        source="contract RollupProcessor { function processDepositsAndWithdrawals(uint256 n) external {} }",
    )
    finding = FindingCandidate(
        detector="zk_verifier",
        title="Settlement bounded by a caller-supplied count not bound to the proof",
        description="ZK settlement boundary mismatch where proof commits to a larger range than the L1 loop processes.",
        impact_score=9.0,
        confidence_score=6.0,
        severity_candidate="critical",
        evidence={
            "rule_id": "settlement_count_not_bound_to_proof",
            "bug_class": "settlement_boundary_mismatch",
            "onchain_detectable": "lead_only",
        },
        affected_functions=["processDepositsAndWithdrawals"],
    )

    suite = generate_detector_invariant_suite(ctx, [finding], tmp_path / "zk")
    test_text = suite.test_path.read_text(encoding="utf-8")
    plan_text = suite.plan_path.read_text(encoding="utf-8")

    assert "address(0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455)" in test_text
    assert "testFuzz_detector_bridge_proof_replay_0" in test_text
    assert "testFuzz_stateful_detector_bridge_proof_replay_0" in test_text
    assert "bytes calldata payload" in test_text
    assert "_statefulReplayNoProfit" in test_text
    assert "bridge/proof domain and replay safety" in plan_text
