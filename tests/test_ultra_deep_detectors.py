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
    assert d.run(_ctx(SOF_LIKE, "ultra-deep-v2"))     # v2 inherits ultra behavior
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


from backend.detectors.ultra_deep import (
    CrossChainReceiverSourceAuthDetector,
    Erc2771MsgSenderSpoofDetector,
    PayableMulticallMsgValueReuseDetector,
    ReinitializableProxyDelegatecallDetector,
    VaultShareDonationInflationDetector,
)


def test_cross_chain_receiver():
    bad = ("contract C { function _lzReceive(uint32 s,bytes32 g,bytes calldata m,address e,bytes calldata x) "
           "internal { _credit(abi.decode(m,(uint))); } function _credit(uint) internal {} }")
    good = ("contract C { mapping(uint32=>bytes32) peers; function _lzReceive(uint32 s,bytes32 g,bytes calldata m,"
            "address e,bytes calldata x) internal { require(g==peers[s]); _credit(abi.decode(m,(uint)));} "
            "function _credit(uint) internal {} }")
    assert CrossChainReceiverSourceAuthDetector().run(_ctx(bad))
    assert not CrossChainReceiverSourceAuthDetector().run(_ctx(good))


def test_vault_donation():
    bad = ("contract V { uint public totalSupply; IERC20 token; function deposit(uint a) external "
           "{ uint s = totalSupply==0 ? a : a*totalSupply/token.balanceOf(address(this)); _mint(msg.sender,s);} "
           "function _mint(address,uint) internal {} }")
    good = ("contract V { uint public totalSupply; uint _totalAssets; function deposit(uint a) external "
            "{ uint s = a*(totalSupply+1000000)/(_totalAssets+1); _totalAssets+=a; _mint(msg.sender,s);} "
            "function _mint(address,uint) internal {} }")
    assert VaultShareDonationInflationDetector().run(_ctx(bad))
    assert not VaultShareDonationInflationDetector().run(_ctx(good))


def test_erc2771_spoof():
    bad = ("contract C is ERC2771Context, Multicall { mapping(address=>uint) bal; "
           "function spend(uint a) external { bal[_msgSender()]-=a; } "
           "function multicall(bytes[] calldata data) external { for(uint i;i<data.length;i++){ address(this).delegatecall(data[i]); } } }")
    good = "contract C is ERC2771Context { mapping(address=>uint) bal; function spend(uint a) external { bal[_msgSender()]-=a; } }"
    assert Erc2771MsgSenderSpoofDetector().run(_ctx(bad))
    assert not Erc2771MsgSenderSpoofDetector().run(_ctx(good))


def test_reinit_proxy():
    bad = "contract P { address logic; function initialize(address _logic) external { logic=_logic; } fallback() external { logic.delegatecall(msg.data); } }"
    good = "contract P { address logic; function initialize(address _logic) external initializer { logic=_logic; } fallback() external { logic.delegatecall(msg.data); } }"
    assert ReinitializableProxyDelegatecallDetector().run(_ctx(bad))
    assert not ReinitializableProxyDelegatecallDetector().run(_ctx(good))


def test_payable_multicall():
    bad = "contract C { function multicall(bytes[] calldata data) external payable { for(uint i;i<data.length;i++){ address(this).delegatecall(data[i]); } } }"
    good = "contract C { function multicall(bytes[] calldata data) external { for(uint i;i<data.length;i++){ address(this).delegatecall(data[i]); } } }"
    assert PayableMulticallMsgValueReuseDetector().run(_ctx(bad))
    assert not PayableMulticallMsgValueReuseDetector().run(_ctx(good))


from backend.detectors.ultra_deep import (
    BatchArrayLengthMismatchDetector,
    LiquidationCollateralNotClearedDetector,
    SignedUnsignedCastMismatchDetector,
)


def test_signed_unsigned_cast():
    bad = "contract C { function f(int amount, uint minOut) external { uint got = uint(amount); require(got >= minOut); } }"
    good = "contract C { function f(int amount, uint minOut) external { require(amount >= 0); uint got = uint(amount); require(got >= minOut); } }"
    assert SignedUnsignedCastMismatchDetector().run(_ctx(bad))
    assert not SignedUnsignedCastMismatchDetector().run(_ctx(good))


def test_batch_array_length():
    bad = "contract C { function airdrop(address[] calldata to, uint[] calldata amt) external { for(uint i;i<to.length;i++){ pay(to[i], amt[i]); } } function pay(address,uint) internal {} }"
    good = "contract C { function airdrop(address[] calldata to, uint[] calldata amt) external { require(to.length==amt.length); for(uint i;i<to.length;i++){ pay(to[i], amt[i]); } } function pay(address,uint) internal {} }"
    assert BatchArrayLengthMismatchDetector().run(_ctx(bad))
    assert not BatchArrayLengthMismatchDetector().run(_ctx(good))


def test_liquidation_not_cleared():
    bad = "contract C { struct O{uint inputAmount;} mapping(uint=>O) ords; function closeOrder(uint id) external { collateralToken.safeTransfer(msg.sender, ords[id].inputAmount); } }"
    good = "contract C { struct O{uint inputAmount;} mapping(uint=>O) ords; function closeOrder(uint id) external { uint a=ords[id].inputAmount; ords[id].inputAmount=0; collateralToken.safeTransfer(msg.sender, a); } }"
    assert LiquidationCollateralNotClearedDetector().run(_ctx(bad))
    assert not LiquidationCollateralNotClearedDetector().run(_ctx(good))
