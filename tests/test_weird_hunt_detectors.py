from pathlib import Path

from backend.core.semantic_index import build_semantic_index
from backend.core.taint import analyze_taint
from backend.detectors.base import TargetContext
from backend.detectors.registry import get_detectors
from backend.detectors.weird_hunt import (
    AccumulatorZeroSupplyDetector,
    ActualReceivedAccountingDetector,
    BitmapClaimCollisionDetector,
    BridgeReplayKeyDetector,
    DuplicateBatchItemDetector,
    ForcedEthAccountingDetector,
    GovernanceSnapshotBypassDetector,
    MerkleClaimBindingDetector,
    MulticallStateCacheDetector,
    OracleFreshnessSequencerDetector,
    PausabilityBypassDetector,
    RewardDebtOrderDetector,
    TryCatchFinalizationDetector,
    WeirdHuntTaintValueFlowDetector,
)


class _Proxy:
    is_proxy = False


def _ctx(src: str, chain: str = "ethereum") -> TargetContext:
    ctx = TargetContext(
        address="0xabc",
        chain=chain,
        profile="ultra-deep-v2",
        onchain=None,
        proxy_info=_Proxy(),
        workspace=Path("."),
        contract_name="T",
        source_files={"T.sol": src},
    )
    ctx.semantic = build_semantic_index(ctx.source_files, ctx.abi)
    ctx.taint = analyze_taint(ctx.semantic)
    return ctx


def _rules(detector, src: str, chain: str = "ethereum") -> set[str]:
    return {f.evidence.get("rule_id") for f in detector.run(_ctx(src, chain=chain))}


def test_registry_includes_weird_hunt_pack_in_ultra_deep_v2():
    names = {d.name for d in get_detectors("ultra-deep-v2")}
    assert "actual_received_accounting" in names
    assert "merkle_claim_binding" in names
    assert "duplicate_batch_item" in names
    assert "weird_hunt_taint_value_flow" in names


def test_actual_received_accounting_detector():
    bad = """
    contract Vault { IERC20 token; function deposit(uint256 amount) external {
      token.transferFrom(msg.sender, address(this), amount); _mint(msg.sender, amount);
    } function _mint(address,uint256) internal {} }
    """
    good = """
    contract Vault { IERC20 token; function deposit(uint256 amount) external {
      uint256 beforeBal = token.balanceOf(address(this)); token.transferFrom(msg.sender, address(this), amount);
      uint256 received = token.balanceOf(address(this)) - beforeBal; _mint(msg.sender, received);
    } function _mint(address,uint256) internal {} }
    """
    d = ActualReceivedAccountingDetector()
    assert "nominal_amount_used_without_received_delta" in _rules(d, bad)
    assert "nominal_amount_used_without_received_delta" not in _rules(d, good)


def test_merkle_claim_binding_detector():
    bad = """
    contract Drop { bytes32 root; function claim(bytes32[] calldata proof, uint256 amount) external {
      bytes32 leaf = keccak256(abi.encode(amount)); require(MerkleProof.verify(proof, root, leaf));
      token.safeTransfer(msg.sender, amount);
    } }
    """
    good = """
    contract Drop { bytes32 root; function claim(bytes32[] calldata proof, uint256 index, address account, address token, uint256 amount) external {
      bytes32 leaf = keccak256(abi.encode(index, account, token, amount, block.chainid)); require(MerkleProof.verify(proof, root, leaf));
      IERC20(token).safeTransfer(account, amount);
    } }
    """
    d = MerkleClaimBindingDetector()
    assert "merkle_leaf_missing_value_or_domain_fields" in _rules(d, bad)
    assert "merkle_leaf_missing_value_or_domain_fields" not in _rules(d, good)


def test_bitmap_claim_collision_detector():
    bad = """
    contract C { mapping(uint256=>uint256) claimedBitMap; function claim(uint256 index) external {
      uint256 word = claimedBitMap[index / 256]; uint256 mask = 1 << index; require(word & mask == 0); claimedBitMap[index / 256] = word | mask;
    } }
    """
    d = BitmapClaimCollisionDetector()
    assert "bitmap_claim_index_collision" in _rules(d, bad)


def test_bridge_replay_key_detector():
    bad = """
    contract Bridge { mapping(bytes32=>bool) processed; function finalize(bytes calldata message, address token, address to, uint256 amount) external {
      bytes32 id = keccak256(abi.encode(message)); require(!processed[id]); processed[id] = true; IERC20(token).safeTransfer(to, amount);
    } }
    """
    good = """
    contract Bridge { mapping(bytes32=>bool) processed; function finalize(uint256 srcChain, address srcSender, uint256 nonce, bytes calldata message, address token, address to, uint256 amount) external {
      bytes32 id = keccak256(abi.encode(block.chainid, address(this), srcChain, srcSender, nonce, message, token, to, amount)); require(!processed[id]); processed[id] = true; IERC20(token).safeTransfer(to, amount);
    } }
    """
    d = BridgeReplayKeyDetector()
    assert "bridge_message_key_missing_domain_fields" in _rules(d, bad)
    assert "bridge_message_key_missing_domain_fields" not in _rules(d, good)


def test_oracle_freshness_detector():
    bad = """
    contract Market { AggregatorV3Interface feed; function borrow(uint256 amount) external {
      (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData(); uint256 value = amount * uint256(answer) / 1e8; _mint(msg.sender, value + updatedAt);
    } function _mint(address,uint256) internal {} }
    """
    d = OracleFreshnessSequencerDetector()
    assert "chainlink_oracle_missing_freshness_or_sequencer_check" in _rules(d, bad, chain="arbitrum")


def test_forced_eth_accounting_detector():
    bad = """
    contract Vault { uint256 totalSupply; function price(uint256 shares) external view returns (uint256) {
      return address(this).balance * shares / totalSupply;
    } }
    """
    d = ForcedEthAccountingDetector()
    assert "native_balance_used_as_accounting" in _rules(d, bad)


def test_trycatch_finalization_detector():
    bad = """
    contract Bridge { mapping(bytes32=>bool) processed; event Failed(); function execute(bytes32 id, Target t, bytes calldata data) external {
      processed[id] = true; try t.execute(data) { } catch { emit Failed(); }
    } }
    """
    d = TryCatchFinalizationDetector()
    assert "message_consumed_before_trycatch_swallow" in _rules(d, bad)


def test_reward_debt_order_detector():
    bad = """
    contract Rewards { IERC20 rewardToken; mapping(address=>uint256) rewardDebt; function claim() external {
      uint256 pending = 10 ether; rewardToken.safeTransfer(msg.sender, pending); rewardDebt[msg.sender] = block.number;
    } }
    """
    d = RewardDebtOrderDetector()
    assert "reward_transferred_before_debt_update" in _rules(d, bad)


def test_accumulator_zero_supply_detector():
    bad = """
    contract Pool { uint256 accRewardPerShare; uint256 totalSupply; function update(uint256 reward) external {
      accRewardPerShare += reward * 1e12 / totalSupply;
    } }
    """
    d = AccumulatorZeroSupplyDetector()
    assert "reward_accumulator_divides_by_zero_supply" in _rules(d, bad)


def test_governance_snapshot_bypass_detector():
    bad = """
    contract Gov { Token token; function vote(uint256 proposalId) external {
      uint256 weight = token.balanceOf(msg.sender); _countVote(proposalId, weight);
    } function _countVote(uint256,uint256) internal {} }
    """
    d = GovernanceSnapshotBypassDetector()
    assert "governance_uses_current_balance_without_snapshot" in _rules(d, bad)


def test_pausability_bypass_detector():
    bad = """
    contract P { modifier whenNotPaused(){_;} function deposit(uint256 amount) external whenNotPaused { _deposit(amount); }
      function batch(uint256 amount) external { _deposit(amount); }
      function _deposit(uint256 amount) internal { token.safeTransfer(msg.sender, amount); }
    }
    """
    d = PausabilityBypassDetector()
    assert "alternate_entrypoint_reaches_paused_sink" in _rules(d, bad)


def test_multicall_state_cache_detector():
    bad = """
    contract M { function multicall(bytes[] calldata data) external payable {
      for (uint256 i; i < data.length; ++i) { (bool ok,) = address(this).delegatecall(data[i]); require(ok); }
    } }
    """
    d = MulticallStateCacheDetector()
    assert "payable_multicall_reuses_msg_value_or_cached_state" in _rules(d, bad)


def test_duplicate_batch_item_detector():
    bad = """
    contract B { function batchClaim(uint256[] calldata ids, uint256[] calldata amounts) external {
      for (uint256 i; i < ids.length; ++i) { claimed[ids[i]] = true; token.safeTransfer(msg.sender, amounts[i]); }
    } }
    """
    d = DuplicateBatchItemDetector()
    assert "batch_loop_no_duplicate_item_guard" in _rules(d, bad)


def test_taint_value_flow_detector():
    bad = """
    contract T { IERC20 token; function claim(bytes calldata payload) external {
      (address recipient, uint256 amount) = abi.decode(payload, (address,uint256)); _pay(recipient, amount);
    } function _pay(address recipient, uint256 amount) internal { token.safeTransfer(recipient, amount); } }
    """
    d = WeirdHuntTaintValueFlowDetector()
    assert "calldata_cross_function_value_sink" in _rules(d, bad)
