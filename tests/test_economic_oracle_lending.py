from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.economic_oracle_lending import EconomicOracleLendingDetector
from backend.detectors.registry import get_detectors


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc",
        chain="ethereum",
        profile="ultra-deep-v2",
        onchain=None,
        proxy_info=None,
        workspace=Path("."),
        contract_name="T",
        source_files={"T.sol": src},
    )


def _rules(src: str) -> set[str]:
    return {f.evidence.get("rule_id") for f in EconomicOracleLendingDetector().run(_ctx(src))}


def test_compound_style_mutable_price_oracle_is_detected():
    src = """
    contract UniswapAnchoredView {
      struct PriceData { uint248 price; bool failoverActive; }
      mapping(bytes32 => PriceData) public prices;
      uint32 public anchorPeriod;
      function getUnderlyingPrice(address cToken) external view returns (uint256) {
        // Comptroller price oracle for a cToken market.
        return priceInternal(keccak256(abi.encode(cToken))) * 1e18;
      }
      function validate(uint256, int256, uint256, int256 currentAnswer) external returns (bool) {
        prices[keccak256(abi.encode(msg.sender))].price = uint248(uint256(currentAnswer));
        return true;
      }
      function pokeFailedOverPrice(bytes32 symbolHash) public { prices[symbolHash].failoverActive = true; }
      function priceInternal(bytes32 symbolHash) internal view returns (uint256) { return prices[symbolHash].price; }
    }
    """
    assert "compound_oracle_lending_bad_debt" in _rules(src)


def test_borrow_capacity_oracle_flow_is_detected():
    src = """
    contract Borrower {
      IComptroller comptroller; Oracle oracle; ICToken cToken;
      function leveredBorrow(address market) external {
        (, uint liquidity,) = comptroller.getAccountLiquidity(msg.sender);
        uint price = oracle.getUnderlyingPrice(market);
        uint maxBorrow = liquidity / price;
        cToken.borrow(maxBorrow);
      }
    }
    """
    assert "oracle_price_controls_borrow_capacity" in _rules(src)


def test_erc4626_exchange_rate_collateral_oracle_is_detected():
    src = """
    contract EdelLikeOracle {
      function collateralPrice(address wrapper) external view returns (uint256) {
        uint256 assets = IERC4626(wrapper).convertToAssets(1e18);
        uint256 supply = IERC20(wrapper).totalSupply();
        return assets * 1e18 / supply;
      }
      function borrowAgainstCollateral(uint256 collateral) external { borrow(collateral); }
      function borrow(uint256) internal {}
    }
    """
    assert "erc4626_exchange_rate_lending_oracle" in _rules(src)


def test_ultra_deep_v2_registry_includes_detector():
    names = {detector.name for detector in get_detectors("ultra-deep-v2")}
    assert "economic_oracle_lending" in names
