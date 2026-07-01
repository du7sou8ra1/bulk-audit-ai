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


def test_graph_simulation_plan_and_probe_generation():
    ctx = _ctx([])
    ctx.protocol_graph = {
        "surfaces": [{"id": "oracle_lending"}],
        "nodes": [
            {"role": "oracle", "label": "oracle", "address": "0x1111111111111111111111111111111111111111", "source": "state_var"},
            {"role": "lending_controller", "label": "comptroller", "address": "0x2222222222222222222222222222222222222222", "source": "state_var"},
            {"role": "asset", "label": "usdc", "address": "0x3333333333333333333333333333333333333333", "source": "state_var"},
        ],
    }
    cand = FindingCandidate(
        detector="economic_oracle_lending",
        title="oracle controls borrow capacity",
        description="x",
        impact_score=9.0,
        evidence={"bug_class": "erc4626_collateral_oracle"},
    )

    assert flashloan_sim.is_graph_sim_eligible(ctx, cand) is True
    plan = flashloan_sim.build_graph_simulation_plan(ctx, cand)
    assert plan["scenario"] == "oracle_lending_bad_debt"
    assert [c["role"] for c in plan["components"]] == ["target", "oracle", "lending_controller"]
    md = flashloan_sim.render_graph_simulation_markdown(plan)
    assert "Graph-Aware Fork Simulation Plan" in md and "borrowed value" in md
    probe = flashloan_sim.build_graph_protocol_probe(ctx.address, plan["components"], plan["scenario"])
    assert "GraphProtocolProbe" in probe
    assert "ORACLE_1.code.length" in probe
    assert "LENDING_CONTROLLER_2.code.length" in probe


def test_generate_graph_aware_simulation_writes_plan_and_safe_probe(tmp_path):
    ctx = _ctx([])
    ctx.protocol_graph = {
        "surfaces": [{"id": "amm_reserve_dependency"}],
        "nodes": [
            {"role": "amm_pair", "label": "pair", "address": "0x1111111111111111111111111111111111111111", "source": "state_var"},
        ],
    }
    cand = FindingCandidate(
        detector="amm_pair_reserve_desync",
        title="pair reserve desync",
        description="x",
        impact_score=9.0,
        evidence={"bug_class": "reserve_desync"},
    )

    res = flashloan_sim.generate_graph_aware_simulation(
        ctx, cand, tmp_path / "graph", rpc_url="", timeout=10
    )
    assert res["generated"] is True and res["scaffold"] is True
    assert res["scenario"] == "amm_reserve_manipulation"
    assert res["runner_status"] == "skipped"
    assert (tmp_path / "graph" / "graph_simulation.json").exists()
    assert (tmp_path / "graph" / "test" / "GraphProtocolProbe.t.sol").exists()
