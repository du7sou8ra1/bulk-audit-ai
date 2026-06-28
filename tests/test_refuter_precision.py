from pathlib import Path

from backend.core.refuter import refute
from backend.detectors.base import FindingCandidate, TargetContext


class _ProxyInfo:
    admin_owner = None
    owner = None
    admin = None
    implementation = None


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc",
        chain="ethereum",
        profile="ultra-deep-v2",
        onchain=None,
        proxy_info=_ProxyInfo(),
        workspace=Path("."),
        contract_name="Target",
        source_files={"Target.sol": src},
    )


def test_deterministic_binding_gate_runs_without_llm_and_refutes_caller_bound_source(monkeypatch):
    monkeypatch.setattr("backend.core.refuter.llm_available", lambda: False)
    ctx = _ctx(
        """
        contract Router {
          function swap(address token, uint256 amount) external {
            address from = msg.sender;
            IERC20(token).transferFrom(from, address(this), amount);
          }
        }
        """
    )
    cand = FindingCandidate(
        detector="approval_drain",
        title="approval drain",
        description="x",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={"attacker_control_binding": {"variable": "from", "role": "source"}},
        affected_functions=["swap"],
    )
    verdict = refute(ctx, cand)
    assert verdict["attempted"] is True
    assert cand.evidence["refuted_concrete"] is True
    assert "caller-bound" in cand.evidence["refutation"]["refutation"]


def test_real_structural_bug_survives_when_no_concrete_binding_control(monkeypatch):
    monkeypatch.setattr("backend.core.refuter.llm_available", lambda: False)
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
        title="initializer takeover",
        description="x",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={"attacker_control_binding": {"variable": "newOwner", "role": "destination"}},
        affected_functions=["initialize"],
    )
    verdict = refute(ctx, cand)
    assert verdict["attempted"] is False
    assert not cand.evidence.get("refuted")
    assert cand.evidence["refutation"]["reason"] == "llm unavailable"
