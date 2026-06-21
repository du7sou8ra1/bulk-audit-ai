"""Noise + inline-guard fixes for arithmetic_logic.

Real scans flagged audited fixed-point primitives (exp/_ln/mulDiv/sqrt) as
"unchecked arithmetic" dozens of times, and flagged inline-guarded mint/burn as
"no access control". Both are false positives.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_arithmetic_noise.py -q
"""
from pathlib import Path

import pytest

from backend.detectors.arithmetic_logic import ArithmeticLogicDetector
from backend.detectors.base import TargetContext


def _ctx(src: str) -> TargetContext:
    return TargetContext(
        address="0xabc", chain="ethereum", profile="ultra-deep",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )


def _titles(src: str) -> str:
    return " || ".join(f.title.lower() for f in ArithmeticLogicDetector().run(_ctx(src)))


LIB_MATH = [
    "contract M { function exp(int256 x) internal pure returns (int256 r) { unchecked { r = x * x + x; } } }",
    "contract M { function _ln(int256 x) private pure returns (int256 r) { unchecked { r = x * 2 + 1; } } }",
    "contract M { function mulDiv(uint a, uint b, uint d) internal pure returns (uint r) { unchecked { r = a * b + d; } } }",
    "contract M { function sqrt(uint y) internal pure returns (uint z) { unchecked { z = y * y + y; } } }",
]


@pytest.mark.parametrize("src", LIB_MATH, ids=["exp", "_ln", "mulDiv", "sqrt"])
def test_library_math_not_flagged_unchecked(src):
    assert "unchecked arithmetic" not in _titles(src), "audited math primitive must not be flagged"


def test_real_unchecked_in_value_fn_still_flagged():
    # not a library-math name -> the unchecked-arithmetic check still runs
    src = "contract V { function reward(uint a, uint b) external { unchecked { uint t = a * b + a; credit[msg.sender] = t; } } mapping(address=>uint) credit; }"
    assert "unchecked arithmetic" in _titles(src)


def test_inline_guarded_mint_not_flagged_no_ac():
    src = "contract T { bytes32 MINTER; function mint(address to, uint amt) external { _checkRole(MINTER); _mint(to, amt); } function _mint(address,uint) internal {} }"
    assert "no access control" not in _titles(src)


def test_unguarded_mint_still_flagged_no_ac():
    src = "contract T { function mint(address to, uint amt) external { _mint(to, amt); } function _mint(address,uint) internal {} }"
    assert "no access control" in _titles(src)
