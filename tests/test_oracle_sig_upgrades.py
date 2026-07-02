"""Roadmap vector upgrades: oracle median-of-spot (UwU) + ERC4626 donation, and the
precise raw-ecrecover zero-address guard. Each: positive must fire, negative silent.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_oracle_sig_upgrades.py -q
"""
from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.oracle_manipulation import OracleManipulationDetector
from backend.detectors.signature_replay import SignatureReplayDetector


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="ultra-deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _oracle(src: str) -> set[str]:
    return {f.evidence.get("rule_id") for f in OracleManipulationDetector().run(_ctx(src))}


def _sig(src: str) -> set[str]:
    return {f.evidence.get("rule_id") for f in SignatureReplayDetector().run(_ctx(src))}


# ---- ORC-MEDIAN-SPOT (UwU Lend) ----
def test_median_of_spot_fires():
    src = """contract Oracle {
  function getPrice(address t) public view returns(uint256){
    uint256[3] memory p;
    p[0]=chainlink.latestAnswer();
    p[1]=curvePool.get_p();
    p[2]=uniPool.slot0();
    return median(p);
  }
}"""
    assert "oracle_aggregated_spot" in _oracle(src)


def test_median_of_chainlink_only_silent():
    src = """contract Oracle {
  function getPrice(address t) public view returns(uint256){
    uint256[2] memory p;
    p[0]=chainlinkA.latestRoundData();
    p[1]=chainlinkB.latestRoundData();
    return median(p);
  }
}"""
    assert "oracle_aggregated_spot" not in _oracle(src)


# ---- ORC-4626-DONATION ----
def test_erc4626_donation_inflation_fires():
    src = """contract Vault {
  function deposit(uint256 assets) external returns(uint256 shares){
    uint256 supply=totalSupply();
    uint256 ta=asset.balanceOf(address(this));
    shares = supply==0 ? assets : assets*supply/ta;
    _mint(msg.sender,shares);
  }
  function redeem(uint256 s) external {}
}"""
    assert "share_inflation_4626" in _oracle(src)


def test_erc4626_virtual_offset_silent():
    src = """contract Vault {
  function deposit(uint256 assets) external returns(uint256 shares){
    uint256 supply=totalSupply()+10**_decimalsOffset;
    uint256 ta=asset.balanceOf(address(this))+1;
    shares = assets*supply/ta;
    _mint(msg.sender,shares);
  }
  function redeem(uint256 s) external {}
}"""
    assert "share_inflation_4626" not in _oracle(src)


# ---- SIG-ECRECOVER-GUARD ----
def test_raw_ecrecover_no_zero_check_fires():
    src = ("contract C { mapping(address=>uint) balances; "
           "function claim(bytes32 d,uint8 v,bytes32 r,bytes32 s) external { "
           "address who = ecrecover(d,v,r,s); balances[who]+=1; } }")
    assert "ecrecover_no_zero_check" in _sig(src)


def test_ecrecover_with_zero_check_silent():
    src = ("contract C { address owner; "
           "function claim(bytes32 d,uint8 v,bytes32 r,bytes32 s,uint nonce,uint deadline) external { "
           "address recoveredAddress = ecrecover(d,v,r,s); "
           "require(recoveredAddress != address(0), \"IS\"); "
           "require(recoveredAddress == owner, \"UA\"); } }")
    assert "ecrecover_no_zero_check" not in _sig(src)


def test_oz_ecdsa_recover_silent():
    src = ("contract C { address owner; "
           "function claim(bytes32 d, bytes calldata sig) external { "
           "address s = ECDSA.recover(d, sig); require(s == owner); } }")
    assert "ecrecover_no_zero_check" not in _sig(src)


# ---- SIG-EIP712-CACHED-CHAINID (cross-fork replay) ----
def test_eip712_cached_chainid_replay_fires():
    # Domain separator cached at deploy from block.chainid, used directly at verify
    # time, with NO recompute guard -> replayable across a chain fork.
    src = """contract Vault {
  bytes32 public immutable DOMAIN_SEPARATOR;
  mapping(address => uint256) public nonces;
  constructor() {
    DOMAIN_SEPARATOR = keccak256(abi.encode(
      keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
      block.chainid, address(this)));
  }
  function permit(address owner, bytes32 structHash, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, structHash));
    address rec = ecrecover(digest, v, r, s);
    require(rec == owner, "bad sig");
    nonces[owner]++;
  }
}"""
    assert "eip712_cached_chainid_replay" in _sig(src)


def test_eip712_oz_recompute_guard_silent():
    # OZ-style: cached separator but a `block.chainid == _cachedChainId` recheck that
    # rebuilds on a fork -> NOT vulnerable, must stay silent.
    src = """contract Safe {
  bytes32 private immutable _cachedDomainSeparator;
  uint256 private immutable _cachedChainId;
  constructor() {
    _cachedChainId = block.chainid;
    _cachedDomainSeparator = _buildDomainSeparator();
  }
  function _domainSeparatorV4() internal view returns (bytes32) {
    if (block.chainid == _cachedChainId) return _cachedDomainSeparator;
    return _buildDomainSeparator();
  }
  function _buildDomainSeparator() private view returns (bytes32) {
    return keccak256(abi.encode(block.chainid, address(this)));
  }
  function permit(bytes32 structHash, bytes calldata sig) external view {
    bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", _domainSeparatorV4(), structHash));
    address rec = ECDSA.recover(digest, sig);
    require(rec == msg.sender);
  }
}"""
    assert "eip712_cached_chainid_replay" not in _sig(src)


def test_eip712_fresh_recompute_silent():
    # No caching at all: separator rebuilt fresh (with block.chainid) each verify -> safe.
    src = """contract Fresh {
  function _domainSeparator() internal view returns (bytes32) {
    return keccak256(abi.encode(block.chainid, address(this)));
  }
  function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s, address owner) external view {
    bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", _domainSeparator(), h));
    address rec = ecrecover(digest, v, r, s);
    require(rec != address(0) && rec == owner);
  }
}"""
    assert "eip712_cached_chainid_replay" not in _sig(src)
