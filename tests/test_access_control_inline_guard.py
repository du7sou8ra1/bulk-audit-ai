"""The #1 false-positive source: access_control flagging functions that ARE
guarded by an INLINE BODY call (not a header modifier). Real exploited-contract
scans (zkSync/ZKSpace, Cork proxy, Pendle) produced 30-50 of these per contract.

A function guarded by requireGovernor/requireMaster/hasRole/_onlyRole()/
if(msg.sender!=x)revert MUST stay silent; a genuinely unguarded one MUST fire.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_access_control_inline_guard.py -q
"""
from pathlib import Path

import pytest

from backend.detectors.access_control import AccessControlDetector
from backend.detectors.base import TargetContext


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="ultra-deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _fired_no_ac(src: str) -> bool:
    return any(
        "no access control" in f.title.lower()
        for f in AccessControlDetector().run(_ctx(src))
    )


# Inline-guard patterns that MUST be recognized (no finding).
GUARDED = [
    # zkSync / ZKSpace family — the exact pattern that caused the FP flood
    'contract C { Gov governance; function setZkSyncAddress(address a) external { governance.requireGovernor(msg.sender); zk = a; } address zk; }',
    'contract C { function setGenesisRoot(bytes32 r) external { requireMaster(msg.sender); root = r; } bytes32 root; }',
    # OZ AccessControl
    'contract C { function setFee(uint f) external { require(hasRole(ADMIN, msg.sender)); fee = f; } uint fee; bytes32 ADMIN; }',
    'contract C { function setOracle(address o) external { _checkRole(ADMIN_ROLE); oracle = o; } address oracle; bytes32 ADMIN_ROLE; }',
    # plain require(msg.sender == ...)
    'contract C { address owner; function setAdmin(address a) external { require(msg.sender == owner, "no"); admin = a; } address admin; }',
    # if (msg.sender != x) revert
    'contract C { address gov; function pause() external { if (msg.sender != gov) revert(); paused = true; } bool paused; }',
    # bare internal guard call
    'contract C { function withdrawToken(address t) external { _onlyOwner(); _sweep(t); } function _onlyOwner() internal {} function _sweep(address) internal {} }',
]

# Genuinely unguarded privileged writes that MUST still fire.
UNGUARDED = [
    'contract C { address public owner; function setOwner(address o) external { owner = o; } }',
    'contract C { address public admin; function setAdmin(address a) external { admin = a; } }',
    'contract C { uint public fee; function setFee(uint f) external { fee = f; } }',
]


@pytest.mark.parametrize("src", GUARDED, ids=[f"guarded_{i}" for i in range(len(GUARDED))])
def test_inline_guarded_stays_silent(src):
    assert not _fired_no_ac(src), "inline body-guard must suppress the no-access-control finding"


@pytest.mark.parametrize("src", UNGUARDED, ids=[f"unguarded_{i}" for i in range(len(UNGUARDED))])
def test_truly_unguarded_still_fires(src):
    assert _fired_no_ac(src), "a genuinely unguarded privileged write must still fire"
