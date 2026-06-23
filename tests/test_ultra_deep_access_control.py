"""Ultra-deep access_control enhancement (rank 2): custom guard-modifier
resolution + policy-hook suppression + higher confidence. DEEP is frozen, so the
SAME contract behaves differently under 'deep' vs 'ultra-deep' (the A/B).
"""
from pathlib import Path

from backend.detectors.access_control import AccessControlDetector
from backend.detectors.base import TargetContext


def _ctx(src, profile):
    return TargetContext(address="0xabc", chain="ethereum", profile=profile,
                         onchain=None, proxy_info=None, workspace=Path("."),
                         contract_name="T", source_files={"T.sol": src})


def _ac(src, profile):
    return [f for f in AccessControlDetector().run(_ctx(src, profile))
            if "no access control" in f.title.lower()]


UNGUARDED = "contract C { function mintReward(address to,uint a) external { _mint(to,a); } }"
CUSTOM_GUARD = ('contract C { mapping(address=>bool) roles; '
                'modifier onlyController(){ require(roles[msg.sender], "auth"); _; } '
                'function mintReward(address to,uint a) external onlyController { _mint(to,a); } }')
POLICY_HOOK = "contract C { address last; function mintVerify(address m) external { last = m; } }"


def test_unguarded_privileged_fires_in_both_modes():
    assert _ac(UNGUARDED, "deep")
    assert _ac(UNGUARDED, "ultra-deep")


def test_custom_modifier_fp_only_in_deep_not_ultra():
    assert _ac(CUSTOM_GUARD, "deep")            # deep keeps the old FP (frozen)
    assert not _ac(CUSTOM_GUARD, "ultra-deep")  # ultra resolves the custom guard


def test_policy_hook_suppressed_only_in_ultra():
    assert _ac(POLICY_HOOK, "deep")
    assert not _ac(POLICY_HOOK, "ultra-deep")


def test_true_positive_higher_confidence_in_ultra():
    d = _ac(UNGUARDED, "deep")[0].confidence_score
    u = _ac(UNGUARDED, "ultra-deep")[0].confidence_score
    assert u > d
