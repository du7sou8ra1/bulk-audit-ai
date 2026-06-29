"""Accuracy suite for ultra-deep v2 detectors."""
from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.registry import get_detectors
from backend.detectors.ultra_deep_v2 import (
    AllowanceDrainRouterDetector,
    AmmPairReserveDesyncDetector,
    BridgeRetryDomainBindingDetector,
    BridgeKeeperMutationDetector,
    BridgeZeroRootAcceptanceDetector,
    ClmmTickBoundaryRoundingDetector,
    ComponentShareAccountingDetector,
    CustodySweepCentralizationDetector,
    DecimalUnitMismatchDetector,
    Erc4626DualAssetRedeemDoubleCountDetector,
    Erc777HookBalanceBypassDetector,
    FlashCycleRoundingWithdrawDetector,
    InvariantPrecisionLossDetector,
    LendingExchangeRateDonationDetector,
    MultisigDelegatecallPayloadDetector,
    ReadOnlyReserveReentrancyDetector,
    SettlementBoundaryMismatchDetector,
    SingleVerifierBridgeConfigDetector,
    ThinLiquiditySpotOracleDetector,
    UnsafeMintMathDetector,
    VerifierAddressSpoofDetector,
    VyperNonreentrantCompilerDetector,
    ZeroValueTransferFromBypassDetector,
    ZeroTransferRewardCheckpointDetector,
)


def _ctx(src: str, profile: str = "ultra-deep-v2") -> TargetContext:
    return TargetContext(
        address="0xabc",
        chain="ethereum",
        profile=profile,
        onchain=None,
        proxy_info=None,
        workspace=Path("."),
        contract_name="T",
        source_files={"T.sol": src},
    )


def _rules(detector, src: str) -> set[str]:
    return {f.evidence.get("rule_id") for f in detector.run(_ctx(src))}


def test_settlement_boundary_mismatch():
    bad = """
    contract Rollup {
      Verifier verifier;
      function processRollup(bytes calldata proofData, uint256 numRealTxs, bytes32[] calldata txHashes) external {
        require(verifier.verify(proofData, publicInputs()));
        for (uint256 i; i < numRealTxs; ++i) { _settle(txHashes[i]); }
      }
      function publicInputs() internal pure returns (bytes32[] memory) {}
      function _settle(bytes32) internal {}
    }
    """
    good = """
    contract Rollup {
      Verifier verifier;
      function processRollup(bytes calldata proofData, uint256 numRealTxs, bytes32[] calldata txHashes) external {
        require(numRealTxs == txHashes.length, "count");
        require(verifier.verify(proofData, publicInputs()));
        for (uint256 i; i < numRealTxs; ++i) { _settle(txHashes[i]); }
      }
      function publicInputs() internal pure returns (bytes32[] memory) {}
      function _settle(bytes32) internal {}
    }
    """
    d = SettlementBoundaryMismatchDetector()
    assert "proof_settlement_count_unbound" in _rules(d, bad)
    assert "proof_settlement_count_unbound" not in _rules(d, good)


def test_bridge_retry_domain_binding():
    bad = """
    contract Bridge {
      mapping(bytes32 => bool) processed;
      function retry(bytes calldata message) external {
        bytes32 h = keccak256(abi.encode(message));
        require(!processed[h], "done");
        processed[h] = true;
        _execute(message);
      }
      function _execute(bytes calldata) internal {}
    }
    """
    good = """
    contract Bridge {
      mapping(bytes32 => bool) processed;
      function retry(uint256 sourceChain, address sourceSender, uint256 nonce, bytes calldata message) external {
        bytes32 h = keccak256(abi.encode(block.chainid, address(this), sourceChain, sourceSender, nonce, message));
        require(!processed[h], "done");
        processed[h] = true;
        _execute(message);
      }
      function _execute(bytes calldata) internal {}
    }
    """
    d = BridgeRetryDomainBindingDetector()
    assert "bridge_retry_hash_missing_domain" in _rules(d, bad)
    assert "bridge_retry_hash_missing_domain" not in _rules(d, good)


def test_decimal_unit_mismatch():
    bad = """
    contract Lending {
      Oracle oracle;
      function collateralValue(address asset, uint256 amount) external view returns (uint256) {
        uint256 price = oracle.getPrice(asset);
        return amount * price / 1e18;
      }
    }
    """
    good = """
    contract Lending {
      Oracle oracle;
      function collateralValue(address asset, uint256 amount) external view returns (uint256) {
        uint256 price = oracle.getPrice(asset);
        uint256 scale = 10 ** IERC20Metadata(asset).decimals();
        return amount * price / scale;
      }
    }
    """
    d = DecimalUnitMismatchDetector()
    assert "oracle_math_hardcoded_scale_no_decimals" in _rules(d, bad)
    assert "oracle_math_hardcoded_scale_no_decimals" not in _rules(d, good)


def test_zero_value_transferfrom_bypass():
    bad = """
    contract Sale {
      IERC20 token;
      mapping(address => bool) claimed;
      function claimReward(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        claimed[msg.sender] = true;
        _mint(msg.sender, 100 ether);
      }
      function _mint(address, uint256) internal {}
    }
    """
    good = """
    contract Sale {
      IERC20 token;
      mapping(address => bool) claimed;
      function claimReward(uint256 amount) external {
        require(amount > 0, "zero");
        token.transferFrom(msg.sender, address(this), amount);
        claimed[msg.sender] = true;
        _mint(msg.sender, amount);
      }
      function _mint(address, uint256) internal {}
    }
    """
    d = ZeroValueTransferFromBypassDetector()
    assert "zero_transferfrom_gates_value_path" in _rules(d, bad)
    assert "zero_transferfrom_gates_value_path" not in _rules(d, good)


def test_component_share_accounting():
    bad = """
    contract IndexVault {
      address[] components;
      uint256 totalSupply;
      function redeem(uint256 shares) external {
        for (uint256 i; i < components.length; ++i) {
          uint256 amt = IERC20(components[i]).balanceOf(address(this)) * shares / totalSupply;
          IERC20(components[i]).transfer(msg.sender, amt);
        }
        _burn(msg.sender, shares);
      }
      function _burn(address, uint256) internal {}
    }
    """
    good = """
    contract IndexVault {
      address[] components;
      uint256 totalSupply;
      mapping(address => uint256) componentBalances;
      function redeem(uint256 shares) external {
        _burn(msg.sender, shares);
        for (uint256 i; i < components.length; ++i) {
          uint256 amt = componentBalances[components[i]] * shares / totalSupply;
          IERC20(components[i]).transfer(msg.sender, amt);
        }
      }
      function _burn(address, uint256) internal {}
    }
    """
    d = ComponentShareAccountingDetector()
    assert "component_redeem_live_balance_share_math" in _rules(d, bad)
    assert "component_redeem_live_balance_share_math" not in _rules(d, good)


def test_zero_transfer_reward_checkpoint():
    bad = """
    contract RoyaltiesLike {
      struct UcrRecord { uint64 depositId; uint64 ldaBalance; uint128 value; }
      mapping(uint128 => mapping(address => uint256)) internal _NUM_UCR_RECORDS_;
      mapping(uint128 => mapping(address => mapping(uint256 => UcrRecord))) internal _UCR_;
      mapping(uint128 => uint256) internal _NUM_DEPOSITS_;
      LDA public LDA_TOKEN;

      function beforeLdaTransfer(address from, address to, uint128 tierId) external {
        require(msg.sender == address(LDA_TOKEN), "lda");
        if (from != address(0)) { _settleUcr(tierId, from); }
        if (to != address(0)) { _settleUcr(tierId, to); }
      }

      function _settleUcr(uint128 tierId, address account) internal returns (uint256) {
        uint256 lastUcrId = _NUM_UCR_RECORDS_[tierId][account];
        UcrRecord memory lastUcrRecord = _UCR_[tierId][account][lastUcrId];
        uint256 lastDepositId = _NUM_DEPOSITS_[tierId];
        uint256 ldaBalance = LDA_TOKEN.tierBalanceOf(tierId, account);
        uint256 newUcrValue = lastUcrRecord.value + 1;
        uint256 newUcrId = lastUcrId + 1;
        _NUM_UCR_RECORDS_[tierId][account] = newUcrId;
        _UCR_[tierId][account][newUcrId] = UcrRecord(uint64(lastDepositId), uint64(ldaBalance), uint128(newUcrValue));
        return newUcrValue;
      }
    }
    """
    good = """
    contract RoyaltiesSafe {
      struct UcrRecord { uint64 depositId; uint64 ldaBalance; uint128 value; }
      mapping(uint128 => mapping(address => uint256)) internal _NUM_UCR_RECORDS_;
      mapping(uint128 => mapping(address => mapping(uint256 => UcrRecord))) internal _UCR_;
      mapping(uint128 => uint256) internal _NUM_DEPOSITS_;
      LDA public LDA_TOKEN;

      function beforeLdaTransfer(address from, address to, uint128 tierId, uint256 amount) external {
        require(msg.sender == address(LDA_TOKEN), "lda");
        require(amount > 0, "zero");
        if (from != address(0)) { _settleUcr(tierId, from); }
        if (to != address(0)) { _settleUcr(tierId, to); }
      }

      function _settleUcr(uint128 tierId, address account) internal returns (uint256) {
        uint256 lastUcrId = _NUM_UCR_RECORDS_[tierId][account];
        UcrRecord memory lastUcrRecord = _UCR_[tierId][account][lastUcrId];
        uint256 lastDepositId = _NUM_DEPOSITS_[tierId];
        uint256 ldaBalance = LDA_TOKEN.tierBalanceOf(tierId, account);
        uint256 newUcrValue = lastUcrRecord.value + 1;
        if (
          lastUcrRecord.depositId == lastDepositId &&
          lastUcrRecord.ldaBalance == ldaBalance &&
          lastUcrRecord.value == newUcrValue
        ) { return newUcrValue; }
        uint256 newUcrId = lastUcrId + 1;
        _NUM_UCR_RECORDS_[tierId][account] = newUcrId;
        _UCR_[tierId][account][newUcrId] = UcrRecord(uint64(lastDepositId), uint64(ldaBalance), uint128(newUcrValue));
        return newUcrValue;
      }
    }
    """
    d = ZeroTransferRewardCheckpointDetector()
    assert "zero_transfer_stacks_reward_records" in _rules(d, bad)
    assert "zero_transfer_stacks_reward_records" not in _rules(d, good)


def test_single_verifier_bridge_config():
    bad = """
    contract OAppConfig {
      function setLayerZeroConfig() external onlyOwner {
        uint256 requiredDVNCount = 1;
        address[] memory dvns = new address[](1);
        _setDVNs(requiredDVNCount, dvns);
      }
      function _setDVNs(uint256, address[] memory) internal {}
    }
    """
    good = """
    contract OAppConfig {
      function setLayerZeroConfig() external onlyOwner {
        uint256 requiredDVNCount = 3;
        address[] memory dvns = new address[](5);
        _setDVNs(requiredDVNCount, dvns);
      }
      function _setDVNs(uint256, address[] memory) internal {}
    }
    """
    d = SingleVerifierBridgeConfigDetector()
    assert "bridge_single_verifier_or_threshold_one" in _rules(d, bad)
    assert "bridge_single_verifier_or_threshold_one" not in _rules(d, good)


def test_allowance_drain_router():
    bad = """
    contract Router {
      function route(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
      }
    }
    """
    good = """
    contract Router {
      mapping(address => bool) approvedTargets;
      mapping(bytes4 => bool) allowedSelector;
      function route(address target, bytes calldata data) external {
        require(approvedTargets[target], "target");
        require(allowedSelector[bytes4(data)], "selector");
        (bool ok,) = target.call(data);
        require(ok);
      }
    }
    """
    d = AllowanceDrainRouterDetector()
    assert "router_unfiltered_target_and_calldata" in _rules(d, bad)
    assert "router_unfiltered_target_and_calldata" not in _rules(d, good)


def test_erc777_hook_balance_bypass():
    bad = """
    interface IERC777 { function transferFrom(address from, address to, uint256 amount) external returns (bool); }
    contract Market {
      IERC777 imBTC;
      mapping(address => uint256) balances;
      function deposit(uint256 amount) external {
        imBTC.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
      }
      function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        imBTC.transferFrom(address(this), msg.sender, amount);
      }
    }
    """
    good = """
    interface IERC777 { function transferFrom(address from, address to, uint256 amount) external returns (bool); }
    contract Market {
      IERC777 imBTC;
      mapping(address => uint256) balances;
      function deposit(uint256 amount) external nonReentrant {
        balances[msg.sender] += amount;
        imBTC.transferFrom(msg.sender, address(this), amount);
      }
    }
    """
    d = Erc777HookBalanceBypassDetector()
    assert "erc777_transfer_hook_before_balance_update" in _rules(d, bad)
    assert "erc777_transfer_hook_before_balance_update" not in _rules(d, good)


def test_read_only_reserve_reentrancy():
    bad = """
    contract LendingOracle {
      IPool pool;
      function donateThenSync(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(pool), amount);
        pool.sync();
      }
      function collateralValue(uint256 amount) external view returns (uint256) {
        (uint112 r0, uint112 r1,) = pool.getReserves();
        return amount * uint256(r0) / uint256(r1);
      }
    }
    """
    good = """
    contract LendingOracle {
      IPool pool;
      uint256 lastPrice;
      function collateralValue(uint256 amount) external view nonReentrantView returns (uint256) {
        return amount * lastPrice / 1e18;
      }
    }
    """
    d = ReadOnlyReserveReentrancyDetector()
    assert "live_reserve_read_without_read_lock" in _rules(d, bad)
    assert "live_reserve_read_without_read_lock" not in _rules(d, good)


def test_bridge_keeper_mutation():
    bad = """
    contract EthCrossChainManager {
      bytes public curEpochConPubKeyBytes;
      function putCurEpochConPubKeyBytes(bytes calldata keys) external { curEpochConPubKeyBytes = keys; }
      function executeCrossChainTx(bytes calldata payload) external {
        (address target, bytes memory data) = abi.decode(payload, (address, bytes));
        (bool ok,) = target.call(data);
        require(ok, "call");
      }
    }
    """
    good = """
    contract EthCrossChainManager {
      mapping(address => bool) trustedTargets;
      mapping(bytes4 => bool) allowedSelector;
      bytes public curEpochConPubKeyBytes;
      function executeCrossChainTx(bytes calldata payload) external {
        (address target, bytes memory data) = abi.decode(payload, (address, bytes));
        require(trustedTargets[target], "target");
        require(allowedSelector[bytes4(data)], "selector");
        (bool ok,) = target.call(data);
        require(ok, "call");
      }
    }
    """
    d = BridgeKeeperMutationDetector()
    assert "bridge_payload_can_call_keeper_mutator" in _rules(d, bad)
    assert "bridge_payload_can_call_keeper_mutator" not in _rules(d, good)


def test_bridge_zero_root_acceptance():
    bad = """
    contract Replica {
      mapping(bytes32 => uint256) public confirmAt;
      function initialize(bytes32 _committedRoot) external {
        confirmAt[_committedRoot] = 1;
      }
      function process(bytes32 root, bytes calldata message) external {
        require(confirmAt[root] != 0, "root");
        _execute(message);
      }
      function _execute(bytes calldata) internal {}
    }
    """
    good = """
    contract Replica {
      mapping(bytes32 => uint256) public confirmAt;
      function initialize(bytes32 _committedRoot) external {
        require(_committedRoot != bytes32(0), "zero");
        confirmAt[_committedRoot] = 1;
      }
      function process(bytes32 root, bytes calldata message) external {
        require(root != bytes32(0), "zero");
        require(confirmAt[root] != 0, "root");
        _execute(message);
      }
      function _execute(bytes calldata) internal {}
    }
    """
    d = BridgeZeroRootAcceptanceDetector()
    assert "bridge_zero_or_unset_root_can_be_confirmed" in _rules(d, bad)
    assert "bridge_zero_or_unset_root_can_be_confirmed" not in _rules(d, good)


def test_verifier_address_spoof():
    bad = """
    contract Portal {
      function verifyAndExecute(address wormholeVerifier, bytes calldata vaa) external {
        (bool ok, bytes memory ret) = wormholeVerifier.staticcall(vaa);
        require(ok && ret.length > 0, "verify");
        _mint(msg.sender, 1 ether);
      }
      function _mint(address, uint256) internal {}
    }
    """
    good = """
    contract Portal {
      address immutable WORMHOLE_CORE;
      mapping(address => bool) trustedVerifier;
      function verifyAndExecute(address wormholeVerifier, bytes calldata vaa) external {
        require(trustedVerifier[wormholeVerifier], "verifier");
        require(wormholeVerifier == WORMHOLE_CORE, "core");
        (bool ok, bytes memory ret) = wormholeVerifier.staticcall(vaa);
        require(ok && ret.length > 0, "verify");
        _mint(msg.sender, 1 ether);
      }
      function _mint(address, uint256) internal {}
    }
    """
    d = VerifierAddressSpoofDetector()
    assert "caller_supplied_verifier_address" in _rules(d, bad)
    assert "caller_supplied_verifier_address" not in _rules(d, good)


def test_vyper_nonreentrant_compiler():
    bad = """
    # @version 0.2.15
    @external
    @nonreentrant('lock')
    def remove_liquidity(amount: uint256):
        pass
    """
    good = """
    # @version 0.3.10
    @external
    @nonreentrant('lock')
    def remove_liquidity(amount: uint256):
        pass
    """
    d = VyperNonreentrantCompilerDetector()
    assert "vyper_broken_nonreentrant_version" in _rules(d, bad)
    assert "vyper_broken_nonreentrant_version" not in _rules(d, good)


def test_thin_liquidity_spot_oracle():
    bad = """
    contract Lending {
      IPair pair;
      function collateralPrice(uint256 amount) external view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        return amount * uint256(r1) / uint256(r0);
      }
    }
    """
    good = """
    contract Lending {
      IPair pair;
      uint256 minLiquidity;
      function collateralPrice(uint256 amount) external view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        require(r0 > minLiquidity && r1 > minLiquidity, "thin");
        return amount * uint256(r1) / uint256(r0);
      }
    }
    """
    d = ThinLiquiditySpotOracleDetector()
    assert "thin_pool_spot_oracle_no_depth_or_twap" in _rules(d, bad)
    assert "thin_pool_spot_oracle_no_depth_or_twap" not in _rules(d, good)


def test_lending_exchange_rate_donation():
    bad = """
    contract HToken {
      IERC20 underlying;
      uint256 totalBorrows;
      uint256 totalReserves;
      uint256 totalSupply;
      function exchangeRateStored() public view returns (uint256) {
        uint256 cash = underlying.balanceOf(address(this));
        return (cash + totalBorrows - totalReserves) / totalSupply;
      }
    }
    """
    good = """
    contract HToken {
      uint256 internalCash;
      uint256 totalBorrows;
      uint256 totalReserves;
      uint256 totalSupply;
      function exchangeRateStored() public view returns (uint256) {
        require(totalSupply > 0, "supply");
        return (internalCash + totalBorrows - totalReserves) / totalSupply;
      }
    }
    """
    d = LendingExchangeRateDonationDetector()
    assert "exchange_rate_from_donatable_cash" in _rules(d, bad)
    assert "exchange_rate_from_donatable_cash" not in _rules(d, good)


def test_clmm_tick_boundary_rounding():
    bad = """
    contract ElasticPool {
      function computeSwapStep(uint160 sqrtP, uint160 targetSqrtP, uint128 liquidity, int24 tick) external pure returns (uint160) {
        uint256 delta = FullMath.mulDiv(uint256(liquidity), uint256(targetSqrtP - sqrtP), uint256(sqrtP));
        return uint160(uint256(sqrtP) + delta);
      }
    }
    """
    good = """
    contract ElasticPool {
      function computeSwapStep(uint160 sqrtP, uint160 targetSqrtP, uint128 liquidity, int24 tick) external returns (uint160 nextSqrtP) {
        uint256 delta = FullMath.mulDiv(uint256(liquidity), uint256(targetSqrtP - sqrtP), uint256(sqrtP));
        nextSqrtP = uint160(uint256(sqrtP) + delta);
        if (nextSqrtP >= targetSqrtP) { crossTick(tick); }
      }
      function crossTick(int24) internal {}
    }
    """
    d = ClmmTickBoundaryRoundingDetector()
    assert "clmm_boundary_rounding_without_cross_guard" in _rules(d, bad)
    assert "clmm_boundary_rounding_without_cross_guard" not in _rules(d, good)


def test_invariant_precision_loss():
    bad = """
    contract StablePool {
      function calcInvariant(uint256 balance, uint256 supply, uint256 amp) external pure returns (uint256 invariant) {
        uint256 rate = balance / supply * 1e18;
        invariant = rate * amp;
      }
    }
    """
    good = """
    contract StablePool {
      function calcInvariant(uint256 balance, uint256 supply, uint256 amp) external pure returns (uint256 invariant) {
        uint256 rate = Math.mulDiv(balance, 1e18, supply);
        invariant = rate * amp;
      }
    }
    """
    d = InvariantPrecisionLossDetector()
    assert "invariant_division_before_multiplication" in _rules(d, bad)
    assert "invariant_division_before_multiplication" not in _rules(d, good)


def test_unsafe_mint_math():
    bad = """
    contract YethLike {
      function mint(uint256 amount, uint256 rate) external {
        uint256 shares;
        unchecked { shares = amount * rate / 1e18; }
        _mint(msg.sender, shares);
      }
      function _mint(address, uint256) internal {}
    }
    """
    good = """
    contract YethLike {
      function mint(uint256 amount, uint256 rate, uint256 minShares) external {
        uint256 shares = Math.mulDiv(amount, rate, 1e18);
        require(shares >= minShares, "min");
        _mint(msg.sender, shares);
      }
      function _mint(address, uint256) internal {}
    }
    """
    d = UnsafeMintMathDetector()
    assert "unchecked_mint_amount_math" in _rules(d, bad)
    assert "unchecked_mint_amount_math" not in _rules(d, good)


def test_flash_cycle_rounding_withdraw():
    bad = """
    contract BunniLike {
      mapping(address => uint256) shares;
      uint256 totalSupply;
      IERC20 token;
      function withdraw(uint256 share) external {
        uint256 assets = (share * token.balanceOf(address(this)) + totalSupply - 1) / totalSupply;
        token.transfer(msg.sender, assets);
        shares[msg.sender] -= share;
      }
    }
    """
    good = """
    contract BunniLike {
      mapping(address => uint256) shares;
      uint256 totalSupply;
      IERC20 token;
      function withdraw(uint256 share, uint256 minOut) external {
        shares[msg.sender] -= share;
        uint256 assets = Math.mulDiv(share, token.balanceOf(address(this)), totalSupply);
        require(assets >= minOut, "minOut");
        token.transfer(msg.sender, assets);
      }
    }
    """
    d = FlashCycleRoundingWithdrawDetector()
    assert "withdraw_rounds_up_before_robust_debit" in _rules(d, bad)
    assert "withdraw_rounds_up_before_robust_debit" not in _rules(d, good)


def test_multisig_delegatecall_payload():
    bad = """
    contract SafeLike {
      mapping(address => bool) owners;
      uint256 threshold;
      function execTransaction(address to, bytes calldata data, uint8 operation, bytes calldata signatures) external {
        checkSignatures(signatures, threshold);
        if (operation == 1) {
          (bool ok,) = to.delegatecall(data);
          require(ok, "delegate");
        }
      }
      function checkSignatures(bytes calldata, uint256) internal view {}
    }
    """
    good = """
    contract SafeLike {
      mapping(address => bool) owners;
      uint256 threshold;
      function execTransaction(address to, bytes calldata data, uint8 operation, bytes calldata signatures) external {
        checkSignatures(signatures, threshold);
        require(operation != Operation.DelegateCall, "no delegatecall");
        (bool ok,) = to.call(data);
        require(ok, "call");
      }
      function checkSignatures(bytes calldata, uint256) internal view {}
    }
    """
    d = MultisigDelegatecallPayloadDetector()
    assert "multisig_signed_delegatecall_payload" in _rules(d, bad)
    assert "multisig_signed_delegatecall_payload" not in _rules(d, good)


def test_custody_sweep_centralization():
    bad = """
    contract HotWallet {
      IERC20 token;
      function sweep(address to) external onlyOwner {
        token.transfer(to, token.balanceOf(address(this)));
      }
    }
    """
    good = """
    contract HotWallet {
      IERC20 token;
      function sweep(address to) external onlyOwner timelock {
        token.transfer(to, token.balanceOf(address(this)));
      }
    }
    """
    d = CustodySweepCentralizationDetector()
    assert "single_admin_can_sweep_custody" in _rules(d, bad)
    assert "single_admin_can_sweep_custody" not in _rules(d, good)



def test_recent_incident_detectors_registered_in_v2():
    names = {d.name for d in get_detectors("ultra-deep-v2")}
    assert "amm_pair_reserve_desync" in names
    assert "erc4626_dual_asset_redeem_double_count" in names


def test_aidc_deferred_burn_debt_pair_sync_detector():
    bad = """
    interface IUniswapV2Pair { function sync() external; }
    contract AIDCToken {
      address public uniswapPair;
      address public deadWallet;
      uint256 public accumulatedBurnAmount;
      uint256 public FEE_DENOMINATOR = 10000;
      function _sellTransfer(address from, address to, uint256 amount) private {
        uint256 feeAmount = amount * 500 / FEE_DENOMINATOR;
        uint256 communityFee = 0;
        uint256 burnAmount = amount * 3000 / FEE_DENOMINATOR;
        accumulatedBurnAmount += burnAmount;
        super._update(from, to, (amount - feeAmount - communityFee));
      }
      function _executeAccumulatedBurn() internal {
        if (accumulatedBurnAmount == 0) return;
        uint256 pairBalance = balanceOf(uniswapPair);
        uint256 actualBurn = accumulatedBurnAmount > pairBalance ? pairBalance : accumulatedBurnAmount;
        if (actualBurn > 0) {
          accumulatedBurnAmount -= actualBurn;
          super._update(uniswapPair, deadWallet, actualBurn);
          IUniswapV2Pair(uniswapPair).sync();
        }
      }
      function balanceOf(address) public view returns (uint256) {}
    }
    """
    good = """
    interface IUniswapV2Pair { function sync() external; }
    contract SafeToken {
      address public uniswapPair;
      address public deadWallet;
      function burnTreasury(uint256 amount) internal {
        super._update(address(this), deadWallet, amount);
        IUniswapV2Pair(uniswapPair).sync();
      }
    }
    """
    d = AmmPairReserveDesyncDetector()
    assert "deferred_burn_debt_burns_pair_then_sync" in _rules(d, bad)
    assert not _rules(d, good)


def test_vault4626_dual_asset_redeem_double_count_detector():
    bad = """
    contract Vault4626Like {
      address asset;
      address nonAssetToken;
      function totalSupply() public view returns (uint256) {}
      function convertToAssets(uint256 shares) public view returns (uint256) {
        return shares * totalAssets() / totalSupply();
      }
      function totalAssets() public view returns (uint256) {
        uint256 usdcInLp = 10;
        uint256 wethInLp = 2;
        uint256 wethQuoted = OracleLibrary.getQuoteAtTick(1, uint128(wethInLp), nonAssetToken, asset);
        uint256 vaultNonAssetQuoted = OracleLibrary.getQuoteAtTick(
          1,
          uint128(IERC20(nonAssetToken).balanceOf(address(this))),
          nonAssetToken,
          asset
        );
        return IERC20(asset).balanceOf(address(this)) + usdcInLp + wethQuoted + vaultNonAssetQuoted;
      }
      function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
        assets = convertToAssets(shares);
        uint256 nonAssetToSend = IERC20(nonAssetToken).balanceOf(address(this)) * shares / totalSupply();
        IERC20(asset).transfer(receiver, assets);
        _safeTransfer(nonAssetToken, receiver, nonAssetToSend);
      }
      function _safeTransfer(address token, address to, uint256 amount) internal {}
    }
    """
    good = """
    contract SafeVault {
      address asset;
      function totalSupply() public view returns (uint256) {}
      function totalAssets() public view returns (uint256) {
        return IERC20(asset).balanceOf(address(this));
      }
      function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
        assets = shares * totalAssets() / totalSupply();
        IERC20(asset).transfer(receiver, assets);
      }
    }
    """
    d = Erc4626DualAssetRedeemDoubleCountDetector()
    assert "erc4626_redeem_double_pays_quoted_non_asset_leg" in _rules(d, bad)
    assert not _rules(d, good)
