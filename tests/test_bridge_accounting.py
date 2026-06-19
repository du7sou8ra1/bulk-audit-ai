"""Tests for the bridge_accounting detector."""
from pathlib import Path

from backend.core.onchain import OnchainClient
from backend.core.proxy_resolver import ProxyInfo
from backend.detectors.base import TargetContext
from backend.detectors.bridge_accounting import BridgeAccountingDetector

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(filename: str) -> TargetContext:
    src = (FIXTURES / filename).read_text(encoding="utf-8")
    return TargetContext(
        address="0x0000000000000000000000000000000000000002",
        chain="ethereum",
        profile="bridge-focused",
        onchain=OnchainClient(rpc_url=""),
        proxy_info=ProxyInfo(),
        workspace=FIXTURES,
        contract_name=filename.replace(".sol", ""),
        source_files={filename: src},
    )


def test_vulnerable_bridge_flags_recovery_and_finalize():
    findings = BridgeAccountingDetector().run(_ctx("VulnerableBridge.sol"))
    titles = " | ".join(f.title.lower() for f in findings)
    assert findings, "expected bridge findings"
    assert "does not clear state" in titles  # replayable recovery
    assert "without proof verification" in titles  # finalization bypass
    assert "cei" in titles  # external transfer before replay mark


def test_non_bridge_contract_is_ignored():
    # SafeVault is a plain vault, not bridge-like -> no bridge findings.
    findings = BridgeAccountingDetector().run(_ctx("SafeVault.sol"))
    assert findings == []


def _inline_ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0x0000000000000000000000000000000000000003",
        chain="ethereum",
        profile="bridge-focused",
        onchain=OnchainClient(rpc_url=""),
        proxy_info=ProxyInfo(),
        workspace=FIXTURES,
        contract_name="X",
        source_files={"X.sol": src},
    )


def test_clear_state_not_masked_by_local_zero_init():
    """Regression: a local `uint x = 0;` must NOT count as clearing deposit state."""
    src = """
    contract Bridge {
        mapping(bytes32 => uint256) public deposits;
        function withdraw() external {}
        function finalize() external {}
        function claimFailedDeposit(bytes32 id, address to, uint256 amount) external {
            uint256 fee = 0;            // local init — must not be treated as a clear
            require(deposits[id] == amount, "no deposit");
            payable(to).transfer(amount + fee);
        }
    }
    """
    findings = BridgeAccountingDetector().run(_inline_ctx(src))
    titles = " | ".join(f.title.lower() for f in findings)
    assert "does not clear state" in titles


def test_proper_state_clear_is_not_flagged_as_replay():
    """A recovery that deletes deposit state should not get the replay finding."""
    src = """
    contract Bridge {
        mapping(bytes32 => uint256) public deposits;
        function withdraw() external {}
        function finalize() external {}
        function claimFailedDeposit(bytes32 id, address to, uint256 amount) external {
            require(deposits[id] == amount, "no deposit");
            require(status == FAILED, "not failed");
            delete deposits[id];
            payable(to).transfer(amount);
        }
    }
    """
    findings = BridgeAccountingDetector().run(_inline_ctx(src))
    titles = " | ".join(f.title.lower() for f in findings)
    assert "does not clear state" not in titles
