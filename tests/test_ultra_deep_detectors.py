"""Ultra-deep new detectors + the hook_pair_burn_sync SOF fix. These run only
under 'ultra-deep'; deep stays frozen.
"""
from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.exploit_2026 import HookPairBurnSyncDetector
from backend.detectors.ultra_deep import (
    ArbitraryFromTransferFromDetector,
    Eip1271SpoofDetector,
    EcrecoverZeroDetector,
)


def _ctx(src, profile="ultra-deep"):
    return TargetContext(address="0xabc", chain="ethereum", profile=profile,
                         onchain=None, proxy_info=None, workspace=Path("."),
                         contract_name="T", source_files={"T.sol": src})


# ---- hook_pair_burn_sync: the SOF burn-before-sync miss ----
SOF_LIKE = """contract T {
  address pair; mapping(address=>uint) _balances;
  function _tokenTransfer(address f,address t,uint a) internal {
    if (t == pair) { _burn(pair, a/100); }
    _balances[f] -= a; _balances[t] += a - a/100;
  }
  function _burn(address x,uint a) internal { _balances[x] -= a; }
}"""
SAFE_TOKEN = ("contract T { mapping(address=>uint) b; "
              "function _transfer(address f,address t,uint a) internal { b[f]-=a; b[t]+=a; } }")


def test_hook_burn_before_sync_fires_only_in_ultra():
    d = HookPairBurnSyncDetector()
    assert d.run(_ctx(SOF_LIKE, "ultra-deep"))        # ultra catches burn-without-sync
    assert not d.run(_ctx(SOF_LIKE, "deep"))          # deep frozen (it required sync too)
    assert not d.run(_ctx(SAFE_TOKEN, "ultra-deep"))  # no pair reduce -> silent


# ---- ecrecover_zero ----
def test_ecrecover_zero():
    bad = ("contract C { address signer; function claim(bytes32 h,uint8 v,bytes32 r,bytes32 s) "
           "external { require(ecrecover(h,v,r,s)==signer); } }")
    good = ("contract C { address signer; function claim(bytes32 h,uint8 v,bytes32 r,bytes32 s) "
            "external { address a=ecrecover(h,v,r,s); require(a!=address(0) && a==signer); } }")
    assert EcrecoverZeroDetector().run(_ctx(bad))
    assert not EcrecoverZeroDetector().run(_ctx(good))


# ---- eip1271_spoof ----
def test_eip1271_spoof():
    bad = ("contract C { function approve(address owner,bytes32 h,bytes memory sig) external "
           "{ require(IERC1271(owner).isValidSignature(h,sig)==0x1626ba7e); _grant(owner);} "
           "function _grant(address) internal {} }")
    good = ("contract C { mapping(address=>bool) isOwner; function approve(address signer,bytes32 h,"
            "bytes memory sig) external { require(isOwner[signer]); "
            "require(IERC1271(signer).isValidSignature(h,sig)==0x1626ba7e);} }")
    assert Eip1271SpoofDetector().run(_ctx(bad))
    assert not Eip1271SpoofDetector().run(_ctx(good))


# ---- arbitrary_from_transferfrom ----
def test_arbitrary_from():
    bad = ("contract C { address token; function pull(address from,uint amt) external "
           "{ IERC20(token).transferFrom(from,address(this),amt);} }")
    good = ("contract C { address token; function deposit(uint amt) external "
            "{ IERC20(token).transferFrom(msg.sender,address(this),amt);} }")
    assert ArbitraryFromTransferFromDetector().run(_ctx(bad))
    assert not ArbitraryFromTransferFromDetector().run(_ctx(good))
