"""Tests for the Foundry fork-PoC generator (no forge required)."""
from pathlib import Path

from backend.core.onchain import OnchainClient
from backend.core.poc_generator import (
    _normalize_type,
    _parse_param_types,
    build_poc_source,
    build_state_invariant_scaffold,
    generate_poc,
    is_poc_eligible,
    is_state_invariant_finding,
)
from backend.core.proxy_resolver import ProxyInfo
from backend.core.scoring import ScoreResult
from backend.detectors.base import FindingCandidate, TargetContext
from backend.models import Classification
from backend.runners.foundry_runner import FORBIDDEN_TOKENS

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_type():
    assert _normalize_type("uint") == "uint256"
    assert _normalize_type("int") == "int256"
    assert _normalize_type("uint8") == "uint8"
    assert _normalize_type("address") == "address"
    assert _normalize_type("bytes32") == "bytes32"
    assert _normalize_type("uint256[]") is None  # arrays unsupported
    assert _normalize_type("MyStruct") is None  # custom types unsupported


def test_parse_param_types():
    assert _parse_param_types("address newImplementation") == ["address"]
    assert _parse_param_types("address target, bytes calldata data") == ["address", "bytes"]
    assert _parse_param_types("") == []
    assert _parse_param_types("Foo calldata s") is None


def test_build_poc_source_is_safe_and_correct():
    src = build_poc_source(
        "0x00000000000000000000000000000000000000aa", "upgradeTo", ["address"], is_upgrade=True
    )
    assert 'abi.encodeWithSignature("upgradeTo(address)"' in src
    assert "vm.prank" in src
    assert "vm.load" in src and "impl slot unchanged" in src
    # Must NOT contain any forbidden broadcast/send/private-key tokens.
    for tok in FORBIDDEN_TOKENS:
        assert tok not in src


def test_is_poc_eligible():
    eligible_score = ScoreResult(9.0, 6.0, "critical", "medium", Classification.LIKELY_CRITICAL_NEEDS_POC, [])
    cand = FindingCandidate(
        detector="proxy_upgrade",
        title="t",
        description="d",
        affected_functions=["upgradeTo"],
        evidence={"has_access_control": False},
    )
    assert is_poc_eligible(cand, eligible_score) is True

    guarded = FindingCandidate(
        detector="proxy_upgrade", title="t", description="d",
        affected_functions=["upgradeTo"], evidence={"has_access_control": True},
    )
    assert is_poc_eligible(guarded, eligible_score) is False

    weak_score = ScoreResult(5.0, 2.0, "medium", "low", Classification.LOW_OR_INFO, [])
    assert is_poc_eligible(cand, weak_score) is False


def test_generate_poc_writes_project(tmp_path):
    src = (FIXTURES / "VulnerableUpgradeable.sol").read_text(encoding="utf-8")
    ctx = TargetContext(
        address="0x00000000000000000000000000000000000000aa",
        chain="ethereum",
        profile="standard",
        onchain=OnchainClient(rpc_url=""),
        proxy_info=ProxyInfo(),
        workspace=tmp_path,
        contract_name="VulnerableUpgradeable",
        source_files={"VulnerableUpgradeable.sol": src},
    )
    cand = FindingCandidate(
        detector="proxy_upgrade",
        title="Unprotected upgradeTo",
        description="d",
        affected_functions=["upgradeTo"],
        evidence={"has_access_control": False},
    )
    meta = generate_poc(ctx, cand, tmp_path)
    assert meta is not None and not meta.get("skipped")
    assert meta["signature"] == "upgradeTo(address)"
    assert (tmp_path / "test" / "Poc.t.sol").exists()
    assert (tmp_path / "foundry.toml").exists()


def test_role_name_is_not_turned_into_a_poc(tmp_path):
    """Regression: governance role names must NOT generate a (bogus) PoC."""
    src = (FIXTURES / "VulnerableUpgradeable.sol").read_text(encoding="utf-8")
    ctx = TargetContext(
        address="0x00000000000000000000000000000000000000aa",
        chain="ethereum",
        profile="governance-focused",
        onchain=OnchainClient(rpc_url=""),
        proxy_info=ProxyInfo(),
        workspace=tmp_path,
        contract_name="VulnerableUpgradeable",
        source_files={"VulnerableUpgradeable.sol": src},
    )
    # Mimics governance_blast_radius Case 2: affected_functions are ROLE NAMES.
    cand = FindingCandidate(
        detector="governance_blast_radius",
        title="Open DEFAULT_ADMIN_ROLE",
        description="d",
        affected_functions=["DEFAULT_ADMIN_ROLE"],
        evidence={"open_roles": {"DEFAULT_ADMIN_ROLE": {"zero": True}}},
    )
    meta = generate_poc(ctx, cand, tmp_path)
    assert meta is not None and meta.get("skipped") is True
    assert not (tmp_path / "test" / "Poc.t.sol").exists()


def test_weird_hunt_state_invariant_scaffold_has_family_template():
    cand = FindingCandidate(
        detector="reward_debt_order",
        title="reward before debt",
        description="d",
        affected_functions=["claim"],
        evidence={"bug_class": "reward_debt_order", "needs_stateful_poc": True},
    )
    assert is_state_invariant_finding(cand) is True
    src = build_state_invariant_scaffold(
        "0x00000000000000000000000000000000000000aa", "claim", "reward_debt_order"
    )
    assert "malicious reward token" in src
    assert "test_invariant_break_claim" in src
