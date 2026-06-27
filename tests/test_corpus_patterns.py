from pathlib import Path

from backend.detectors.base import TargetContext
from backend.detectors.corpus_patterns import CorpusPatternDetector
from backend.detectors.registry import get_detectors


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


def _rules(src: str, profile: str = "ultra-deep-v2") -> set[str]:
    return {f.evidence.get("rule_id") for f in CorpusPatternDetector().run(_ctx(src, profile))}


def test_corpus_detector_is_v2_only_and_registered():
    assert CorpusPatternDetector in {type(d) for d in get_detectors("ultra-deep-v2")}
    assert CorpusPatternDetector not in {type(d) for d in get_detectors("ultra-deep")}
    src = """
    contract Swap {
      Router router;
      function swap(uint256 amount) external {
        router.exactInput(amount);
      }
    }
    """
    assert _rules(src, "deep") == set()
    assert "corpus_slippage_deadline" in _rules(src)


def test_slippage_and_deadline_patterns():
    bad = """
    contract Zap {
      Router router;
      function swap(uint256 amountIn) external {
        router.exactInput(amountIn);
      }
    }
    """
    good = """
    contract Zap {
      Router router;
      function swap(uint256 amountIn, uint256 minOut, uint256 deadline) external {
        require(block.timestamp <= deadline, "expired");
        uint256 amountOut = router.exactInput(amountIn);
        require(amountOut >= minOut, "slippage");
      }
    }
    """
    bad_rules = _rules(bad)
    good_rules = _rules(good)
    assert "corpus_slippage_deadline" in bad_rules
    assert "corpus_slippage_deadline" not in good_rules


def test_chainlink_staleness_pattern():
    bad = """
    contract Pricer {
      Aggregator feed;
      function price() external view returns (int256) {
        (, int256 answer,,,) = feed.latestRoundData();
        return answer;
      }
    }
    """
    good = """
    contract Pricer {
      Aggregator feed;
      function price() external view returns (int256) {
        (uint80 roundId, int256 answer,, uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(updatedAt + 1 hours >= block.timestamp, "stale");
        require(answeredInRound >= roundId, "round");
        return answer;
      }
    }
    """
    assert "corpus_chainlink_staleness" in _rules(bad)
    assert "corpus_chainlink_staleness" not in _rules(good)


def test_unbounded_loop_dos_pattern():
    bad = """
    contract Distributor {
      address[] users;
      Token token;
      function distribute() external {
        for (uint256 i; i < users.length; ++i) {
          token.transfer(users[i], 1 ether);
        }
      }
    }
    """
    good = """
    contract Distributor {
      address[] users;
      Token token;
      function distribute(uint256 start, uint256 limit) external {
        uint256 end = start + limit;
        for (uint256 i = start; i < users.length && i < end; ++i) {
          token.transfer(users[i], 1 ether);
        }
      }
    }
    """
    assert "corpus_unbounded_loop_dos" in _rules(bad)
    assert "corpus_unbounded_loop_dos" not in _rules(good)


def test_low_level_call_pattern():
    bad = """
    contract Executor {
      function pay(address target, bytes calldata data) external {
        target.call(data);
      }
    }
    """
    good = """
    contract Executor {
      function pay(address target, bytes calldata data) external {
        (bool success,) = target.call(data);
        require(success, "call failed");
      }
    }
    """
    assert "corpus_low_level_call_unchecked" in _rules(bad)
    assert "corpus_low_level_call_unchecked" not in _rules(good)


def test_signature_replay_pattern():
    bad = """
    contract Claims {
      function claim(bytes32 digest, bytes calldata sig) external {
        address signer = ECDSA.recover(digest, sig);
        require(signer == msg.sender, "bad");
        _mint(msg.sender, 1 ether);
      }
      function _mint(address, uint256) internal {}
    }
    """
    good = """
    contract Claims {
      mapping(bytes32 => bool) usedSignatures;
      bytes32 DOMAIN_SEPARATOR;
      function claim(bytes32 action, uint256 deadline, bytes calldata sig) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(DOMAIN_SEPARATOR, block.chainid, address(this), action, deadline));
        require(!usedSignatures[digest], "used");
        usedSignatures[digest] = true;
        address signer = ECDSA.recover(digest, sig);
        require(signer == msg.sender, "bad");
      }
    }
    """
    assert "corpus_signature_replay" in _rules(bad)
    assert "corpus_signature_replay" not in _rules(good)


def test_zero_address_privileged_setter_pattern():
    bad = """
    contract Admin {
      address public guardian;
      function setGuardian(address newGuardian) external onlyOwner {
        guardian = newGuardian;
      }
    }
    """
    good = """
    contract Admin {
      address public guardian;
      function setGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "zero");
        guardian = newGuardian;
      }
    }
    """
    assert "corpus_zero_address_privileged_setter" in _rules(bad)
    assert "corpus_zero_address_privileged_setter" not in _rules(good)


def test_division_before_multiplication_pattern():
    bad = """
    contract Rewards {
      function rewardValue(uint256 amount, uint256 price, uint256 shares) external pure returns (uint256) {
        uint256 rate = amount / shares;
        uint256 value = rate * price;
        return value;
      }
    }
    """
    good = """
    contract Rewards {
      function rewardValue(uint256 amount, uint256 price, uint256 shares) external pure returns (uint256) {
        return Math.mulDiv(amount, price, shares);
      }
    }
    """
    assert "corpus_division_before_multiplication" in _rules(bad)
    assert "corpus_division_before_multiplication" not in _rules(good)
