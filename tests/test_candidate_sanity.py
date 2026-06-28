from pathlib import Path

from backend.core.candidate_sanity import apply_candidate_sanity
from backend.detectors.access_control import AccessControlDetector
from backend.detectors.base import FindingCandidate, TargetContext
from backend.detectors.proxy_upgrade import ProxyUpgradeDetector


class _NoChain:
    available = False


class _InitializedChain:
    available = True

    def call_typed(self, _address, signature, **_kwargs):
        if signature in {"isInitialized()", "initialized()"}:
            return True
        return None


class _ZeroOwnerChain:
    available = True

    def call_typed(self, _address, signature, **_kwargs):
        if signature == "owner()":
            return "0x0000000000000000000000000000000000000000"
        return None


class _ProxyInfo:
    admin_owner = None
    owner = None
    admin = None
    implementation = None


def _ctx(src: str, *, abi=None, onchain=None) -> TargetContext:
    return TargetContext(
        address="0x0000000000000000000000000000000000000001",
        chain="ethereum",
        profile="ultra-deep-v2",
        onchain=onchain or _NoChain(),
        proxy_info=_ProxyInfo(),
        workspace=Path("."),
        contract_name="Target",
        source_files={"Target.sol": src},
        abi=abi,
    )


def test_absent_function_is_suppressed_before_scoring():
    ctx = _ctx(
        "contract L1StandardBridge { function bridgeERC20(address token, uint256 amount) external {} }",
        abi=[{"type": "function", "name": "bridgeERC20", "inputs": []}],
    )
    cand = FindingCandidate(
        detector="bridge_zero_root_acceptance",
        title="Bridge root gate lacks an explicit zero-root rejection: relayMessage",
        description="test",
        impact_score=9.5,
        confidence_score=6.0,
        evidence={"function": "relayMessage"},
        affected_functions=["relayMessage"],
    )

    assert apply_candidate_sanity(ctx, [cand]) == 1
    assert cand.evidence["suppressed"] is True
    assert "absent" in cand.evidence["suppressed_reason"]


def test_public_vault_withdraw_user_exit_is_not_access_control_critical():
    src = """
    contract Vault {
      mapping(address => uint256) public shares;
      IERC20 asset;
      function withdraw(uint256 amount) external {
        shares[msg.sender] -= amount;
        _burn(msg.sender, amount);
        asset.transfer(msg.sender, amount);
      }
    }
    """
    findings = AccessControlDetector().run(_ctx(src))
    assert not [f for f in findings if f.affected_functions == ["withdraw"]]


def test_proxy_call_if_not_admin_counts_as_upgrade_guard():
    src = """
    contract Proxy {
      modifier proxyCallIfNotAdmin() { _; }
      function upgradeTo(address impl) external proxyCallIfNotAdmin {
        _setImplementation(impl);
      }
      function _setImplementation(address) internal {}
    }
    """
    findings = ProxyUpgradeDetector().run(_ctx(src))
    upgrade = [f for f in findings if f.affected_functions == ["upgradeTo"]]
    assert upgrade
    assert "unprotected" not in upgrade[0].title.lower()
    assert upgrade[0].confidence_score <= 3


def test_live_initialized_target_suppresses_initializer_takeover():
    ctx = _ctx(
        """
        contract Bridge {
          address public owner;
          function initialize(address newOwner) external { owner = newOwner; }
          function isInitialized() external view returns (bool) { return true; }
        }
        """,
        abi=[
            {"type": "function", "name": "initialize", "inputs": []},
            {"type": "function", "name": "isInitialized", "inputs": []},
        ],
        onchain=_InitializedChain(),
    )
    cand = FindingCandidate(
        detector="unprotected_initializer",
        title="Public initializer writes a privilege slot with no guard: initialize",
        description="test",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={"function": "initialize"},
        affected_functions=["initialize"],
    )

    assert apply_candidate_sanity(ctx, [cand]) == 1
    assert cand.evidence["suppressed"] is True
    assert "isInitialized" in cand.evidence["suppressed_reason"]


def test_never_initialized_liveness_is_evidence_not_immediate_suppression():
    ctx = _ctx(
        """
        contract Init {
          address public owner;
          function initialize(address newOwner) external { owner = newOwner; }
        }
        """,
        onchain=_ZeroOwnerChain(),
    )
    cand = FindingCandidate(
        detector="unprotected_initializer",
        title="Public initializer writes a privilege slot with no guard: initialize",
        description="test",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={"function": "initialize"},
        affected_functions=["initialize"],
    )

    assert apply_candidate_sanity(ctx, [cand]) == 0
    assert cand.evidence["never_initialized"] is True
    assert cand.evidence["liveness_getters"][0]["getter"] == "owner()"


def test_amm_factory_one_time_initializer_is_suppressed():
    ctx = _ctx(
        """
        contract CLPool {
          address public factory;
          struct Slot0 { uint160 sqrtPriceX96; }
          Slot0 public slot0;
          function initialize(uint160 price) external {
            require(factory == address(0), "AI");
            require(slot0.sqrtPriceX96 == 0, "AI");
            factory = msg.sender;
            slot0.sqrtPriceX96 = price;
          }
        }
        """
    )
    cand = FindingCandidate(
        detector="unprotected_initializer",
        title="Public initializer writes a privilege slot with no guard: initialize",
        description="test",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={"function": "initialize"},
        affected_functions=["initialize"],
    )
    assert apply_candidate_sanity(ctx, [cand]) == 1
    assert "AMM pool one-time" in cand.evidence["suppressed_reason"]


def test_caller_bound_transferfrom_binding_refutes_approval_drain():
    ctx = _ctx(
        """
        contract Router {
          function swap(address token, address to, uint256 amount) external {
            address from = msg.sender;
            IERC20(token).transferFrom(from, address(this), amount);
            IERC20(token).transfer(to, amount);
          }
        }
        """
    )
    cand = FindingCandidate(
        detector="approval_drain",
        title="transferFrom may drain third-party approvals: swap",
        description="test",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={
            "function": "swap",
            "attacker_control_binding": {"variable": "from", "role": "source"},
        },
        affected_functions=["swap"],
    )
    assert apply_candidate_sanity(ctx, [cand]) == 1
    assert cand.evidence["refuted_concrete"] is True
    assert "caller-bound" in cand.evidence["suppressed_reason"]


def test_real_structural_initializer_bug_survives_binding_gate():
    ctx = _ctx(
        """
        contract Init {
          address public owner;
          function initialize(address newOwner) external {
            owner = newOwner;
          }
        }
        """
    )
    cand = FindingCandidate(
        detector="unprotected_initializer",
        title="Public initializer writes a privilege slot with no guard: initialize",
        description="test",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={
            "function": "initialize",
            "attacker_control_binding": {"variable": "newOwner", "role": "destination"},
        },
        affected_functions=["initialize"],
    )
    assert apply_candidate_sanity(ctx, [cand]) == 0
    assert not cand.evidence.get("refuted")
