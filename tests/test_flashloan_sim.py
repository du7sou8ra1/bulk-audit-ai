"""Tests for the fork oracle/flash-loan simulator (non-forge logic).

The actual `forge test --fork-url` run needs a fork RPC + Foundry, so here we
test: eligibility, price-view selection from the ABI, the generated Solidity, and
the scaffold-fallback path when no price-view/token can be identified.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_flashloan_sim.py -q
"""
from pathlib import Path

from backend.core import flashloan_sim
from backend.detectors.base import FindingCandidate, TargetContext


def _ctx(abi) -> TargetContext:
    return TargetContext(
        address="0x000000000000000000000000000000000000dEaD",
        chain="ethereum", profile="oracle-focused",
        onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="V", source_files={"V.sol": "contract V {}"}, abi=abi,
    )


def test_eligibility():
    oracle = FindingCandidate(detector="oracle_manipulation", title="x", description="y",
                              evidence={"bug_class": "oracle"})
    other = FindingCandidate(detector="proxy_upgrade", title="x", description="y",
                             evidence={"bug_class": "access_control"})
    assert flashloan_sim.is_sim_eligible(oracle) is True
    assert flashloan_sim.is_sim_eligible(other) is False


def test_pick_price_view():
    abi = [
        {"type": "function", "name": "owner", "stateMutability": "view",
         "inputs": [], "outputs": [{"type": "address"}]},
        {"type": "function", "name": "pricePerShare", "stateMutability": "view",
         "inputs": [], "outputs": [{"type": "uint256"}]},
    ]
    assert flashloan_sim._pick_price_view(_ctx(abi)) == "pricePerShare"
    # no view-uint getter -> None
    assert flashloan_sim._pick_price_view(_ctx([
        {"type": "function", "name": "owner", "stateMutability": "view",
         "inputs": [], "outputs": [{"type": "address"}]}])) is None
    # a price getter that REQUIRES args can't be auto-called -> skipped
    assert flashloan_sim._pick_price_view(_ctx([
        {"type": "function", "name": "getRate", "stateMutability": "view",
         "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}]}])) is None


def test_donation_probe_solidity():
    src = flashloan_sim.build_donation_probe("0xTARGET", "0xTOKEN", "pricePerShare")
    assert "0xTARGET" in src and "0xTOKEN" in src
    assert "pricePerShare()" in src
    assert "DO NOT BROADCAST" in src
    assert "priceAfter != priceBefore" in src          # the manipulation assertion
    assert "_setBalance" in src and "keccak256(abi.encode(who, slot))" in src


def test_flashloan_scaffold_solidity():
    src = flashloan_sim.build_flashloan_scaffold("0xTARGET", None)
    assert "flashLoanSimple" in src and "0xTARGET" in src
    assert "TODO" in src and "DO NOT BROADCAST" in src


def test_generate_falls_back_to_scaffold_without_onchain(tmp_path):
    # onchain=None => no underlying token => scaffold path, no forge needed.
    abi = [{"type": "function", "name": "pricePerShare", "stateMutability": "view",
            "inputs": [], "outputs": [{"type": "uint256"}]}]
    cand = FindingCandidate(detector="oracle_manipulation", title="x", description="y",
                            evidence={"bug_class": "oracle"}, affected_functions=["pricePerShare"])
    res = flashloan_sim.generate_and_run(
        _ctx(abi), cand, tmp_path / "sim", rpc_url="", timeout=10)
    assert res["generated"] is False and res["scaffold"] is True
    assert (tmp_path / "sim" / "test" / "FlashLoanProbe.t.sol").exists()
