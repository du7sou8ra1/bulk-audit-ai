"""Detector tests against the vulnerable + safe fixtures.

Ensures the scanner produces findings on a vulnerable contract and does NOT
invent criticals on a safe one.
"""
from pathlib import Path

from backend.core.onchain import OnchainClient
from backend.core.proxy_resolver import ProxyInfo
from backend.detectors.arbitrary_call import ArbitraryCallDetector
from backend.detectors.base import TargetContext
from backend.detectors.proxy_upgrade import ProxyUpgradeDetector

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(filename: str) -> TargetContext:
    src = (FIXTURES / filename).read_text(encoding="utf-8")
    return TargetContext(
        address="0x0000000000000000000000000000000000000001",
        chain="ethereum",
        profile="standard",
        onchain=OnchainClient(rpc_url=""),  # offline => available is False
        proxy_info=ProxyInfo(),
        workspace=FIXTURES,
        contract_name=filename.replace(".sol", ""),
        source_files={filename: src},
    )


def test_vulnerable_upgrade_flagged():
    findings = ProxyUpgradeDetector().run(_ctx("VulnerableUpgradeable.sol"))
    titles = [f.title for f in findings]
    assert any("unprotected upgrade" in t.lower() for t in titles)
    crit = [f for f in findings if "upgradeTo" in (f.affected_functions or [])]
    assert crit and crit[0].confidence_score >= 5


def test_vulnerable_arbitrary_call_flagged():
    findings = ArbitraryCallDetector().run(_ctx("VulnerableUpgradeable.sol"))
    kinds = {f.evidence.get("kind") for f in findings}
    assert "call" in kinds
    assert "delegatecall" in kinds
    # delegatecall candidate should be high impact + unguarded.
    deleg = [f for f in findings if f.evidence.get("kind") == "delegatecall"]
    assert deleg and deleg[0].impact_score >= 8


def test_safe_upgrade_not_critical():
    findings = ProxyUpgradeDetector().run(_ctx("SafeVault.sol"))
    # upgradeTo is guarded -> recorded but low confidence, not an unprotected critical.
    for f in findings:
        if "upgradeTo" in (f.affected_functions or []):
            assert "unprotected" not in f.title.lower()
            assert f.confidence_score <= 3
