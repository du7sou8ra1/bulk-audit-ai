"""Fork-based oracle / flash-loan manipulation simulator (v0.5).

Turns `oracle_manipulation` CANDIDATES into CONFIRMATIONS where it can be done
honestly and automatically:

  * DONATION / balanceOf-manipulation (Venus exchange-rate, ERC4626 inflation,
    BlindBox): on a local fork, read the protocol's reported price/share value,
    inflate the target's underlying-token balance (simulating an unprivileged
    donation, via a self-contained storage-slot finder — no forge-std needed),
    re-read the price, and assert it MOVED. A price that moves from a pure
    donation is unprivileged-manipulable -> CONFIRMED. A price that doesn't move
    (oracle/internal-accounting based) -> the candidate is refuted by simulation.

  * AMM-spot flash-loan: needs the specific pool + attack sequence, which can't be
    auto-generated safely, so this emits a runnable Aave-v3 flash-loan SCAFFOLD
    with the invariant assertion pre-written (never auto-counted as passing).

SAFETY: identical guarantees to poc_generator — local `forge test --fork-url`
only, ffi disabled, no broadcast/keys (the foundry_runner refuses those tokens).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..detectors.base import FindingCandidate, TargetContext

logger = logging.getLogger("bulkauditai.flashloan_sim")

_PRICE_NAME_HINTS = (
    "price", "share", "rate", "totalassets", "pricepershare", "convertto",
    "exchangerate", "getrate", "lastprice", "spotprice", "value", "getamountout",
)
_TOKEN_GETTERS = ("asset()", "token()", "underlying()", "want()", "stable()",
                  "collateral()", "baseToken()", "wantToken()")

CHEAT_ADDR = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"


def is_sim_eligible(candidate: FindingCandidate) -> bool:
    return str((candidate.evidence or {}).get("bug_class", "")) == "oracle"


def _pick_price_view(ctx: TargetContext) -> str | None:
    """A zero-arg view function returning a single uint — the 'reported price'."""
    abi = ctx.abi
    if not isinstance(abi, list):
        return None
    best = None
    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        if item.get("stateMutability") not in ("view", "pure"):
            continue
        if item.get("inputs"):  # must be callable with no args
            continue
        outs = item.get("outputs") or []
        if len(outs) != 1 or not str(outs[0].get("type", "")).startswith("uint"):
            continue
        name = item.get("name", "")
        low = name.lower()
        if any(h in low for h in _PRICE_NAME_HINTS):
            return name  # strong name match wins immediately
        best = best or name
    return best


def _find_underlying_token(ctx: TargetContext) -> str | None:
    oc = ctx.onchain
    if oc is None:
        return None
    for getter in _TOKEN_GETTERS:
        try:
            addr = oc.try_address_getter(ctx.address, getter)
        except Exception:  # noqa: BLE001
            addr = None
        if addr:
            return addr
    return None


def _foundry_toml() -> str:
    return ("[profile.default]\nsrc='src'\nout='out'\ntest='test'\nlibs=[]\n"
            "ffi=false\nfs_permissions=[]\n")


_DONATION_PROBE = """// SPDX-License-Identifier: MIT
// AUTO-GENERATED ORACLE-MANIPULATION FORK PROBE — local fork only. DO NOT BROADCAST.
// PASSES iff an unprivileged token donation moves the protocol's reported price.
pragma solidity ^0.8.19;

interface Vm {
    function load(address,bytes32) external view returns (bytes32);
    function store(address,bytes32,bytes32) external;
}
interface IERC20 { function balanceOf(address) external view returns (uint256); }
interface IPriced { function __PRICE_FN__() external view returns (uint256); }

contract OracleManipProbe {
    Vm constant vm = Vm(__CHEAT__);
    address constant TARGET = __TARGET__;
    address constant TOKEN  = __TOKEN__;

    function test_donation_moves_reported_price() external {
        uint256 priceBefore = IPriced(TARGET).__PRICE_FN__();
        uint256 bal = IERC20(TOKEN).balanceOf(TARGET);
        uint256 donation = bal == 0 ? 1e24 : bal * 2;       // simulate an attacker donation
        require(_setBalance(TOKEN, TARGET, bal + donation), "balance slot not found");
        uint256 priceAfter = IPriced(TARGET).__PRICE_FN__();
        // If a PURE donation changes the reported price, it is unprivileged-manipulable.
        require(priceAfter != priceBefore,
            "price not balance-sensitive: donation did not move it (likely oracle/internal-accounting)");
    }

    // Self-contained storage `deal` (forge-std stdstore, inlined): brute-force the
    // ERC20 balance mapping slot, write the new balance, verify via balanceOf.
    function _setBalance(address token, address who, uint256 amount) internal returns (bool) {
        for (uint256 slot = 0; slot < 40; slot++) {
            bytes32 key = keccak256(abi.encode(who, slot));
            bytes32 prev = vm.load(token, key);
            vm.store(token, key, bytes32(amount));
            if (IERC20(token).balanceOf(who) == amount) return true;
            vm.store(token, key, prev); // restore and keep searching
        }
        return false;
    }
}
"""

_FLASHLOAN_SCAFFOLD = """// SPDX-License-Identifier: MIT
// AUTO-GENERATED FLASH-LOAN SCAFFOLD — local fork only. DO NOT BROADCAST.
// Spot-AMM manipulation needs the specific pool + attack sequence; complete the
// 2 TODO blocks. Never auto-counted as a passing PoC.
pragma solidity ^0.8.19;

interface Vm { function createSelectFork(string calldata) external returns (uint256); }
interface IAavePool {
    function flashLoanSimple(address receiver, address asset, uint256 amount,
        bytes calldata params, uint16 referralCode) external;
}
interface IPriced { function __PRICE_FN__() external view returns (uint256); }

contract FlashLoanProbe {
    address constant TARGET = __TARGET__;
    // Aave v3 Pool (mainnet). Swap for the right lender/chain.
    IAavePool constant POOL = IAavePool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);

    function executeOperation(address asset, uint256 amount, uint256 premium,
        address, bytes calldata) external returns (bool) {
        uint256 priceBefore = IPriced(TARGET).__PRICE_FN__();
        // TODO 1: use `amount` to skew the AMM pool the target prices against.
        // TODO 2: call the target's profit path (borrow/mint/redeem) at the skewed price.
        uint256 priceAfter = IPriced(TARGET).__PRICE_FN__();
        require(priceAfter != priceBefore, "spot price unaffected");
        // repay handled by approving amount+premium to POOL.
        return true;
    }

    function test_flashloan_attack() external {
        // TODO: POOL.flashLoanSimple(address(this), <asset>, <amount>, "", 0);
        // then assert attacker profit > 0.
    }
}
"""


def build_donation_probe(target: str, token: str, price_fn: str) -> str:
    return (_DONATION_PROBE
            .replace("__CHEAT__", CHEAT_ADDR)
            .replace("__TARGET__", target)
            .replace("__TOKEN__", token)
            .replace("__PRICE_FN__", price_fn))


def build_flashloan_scaffold(target: str, price_fn: str | None) -> str:
    return (_FLASHLOAN_SCAFFOLD
            .replace("__TARGET__", target)
            .replace("__PRICE_FN__", price_fn or "pricePerShare"))


_GRAPH_SIM_DETECTORS = {
    "economic_oracle_lending",
    "oracle_manipulation",
    "thin_liquidity_spot_oracle",
    "lending_exchange_rate_donation",
    "vault_share_donation_inflation",
    "erc4626_dual_asset_redeem_double_count",
    "amm_pair_reserve_desync",
    "hook_pair_burn_sync",
}
_GRAPH_SIM_BUG_CLASSES = {
    "oracle",
    "erc4626_collateral_oracle",
    "vault_accounting",
    "amm_reserve_desync",
    "reserve_desync",
    "lending_exchange_rate_donation",
}
_GRAPH_SIM_ROLES = {
    "oracle",
    "lending_controller",
    "lending_market",
    "erc4626_vault",
    "amm_pair",
    "router",
    "strategy",
    "verifier",
    "bridge_messenger",
}

_GRAPH_PROTOCOL_PROBE = """// SPDX-License-Identifier: MIT
// AUTO-GENERATED GRAPH-AWARE FORK CONTEXT PROBE - local fork only. DO NOT BROADCAST.
// It validates that the resolved protocol-group addresses have code and records
// the scenario plan. It is NOT exploit proof by itself.
pragma solidity ^0.8.19;

contract GraphProtocolProbe {
    address constant TARGET = __TARGET__;
__COMPONENT_CONSTANTS__

    function test_protocol_components_have_code() external view {
        require(TARGET.code.length > 0, "target has no code on fork");
__COMPONENT_ASSERTS__
    }

    function test_attack_scenario_plan_is_bound() external pure {
        bytes32 scenario = keccak256(bytes("__SCENARIO__"));
        require(scenario != bytes32(0), "empty scenario");
    }
}
"""


def is_graph_sim_eligible(ctx: TargetContext, candidate: FindingCandidate) -> bool:
    graph = getattr(ctx, "protocol_graph", None) or {}
    components = _graph_components(ctx)
    if len(components) < 2:
        return False
    detector = str(candidate.detector or "")
    bug_class = str((candidate.evidence or {}).get("bug_class") or "")
    if detector in _GRAPH_SIM_DETECTORS or bug_class in _GRAPH_SIM_BUG_CLASSES:
        return True
    surface_ids = {str(surface.get("id") or "") for surface in graph.get("surfaces") or []}
    return bool(surface_ids & {"oracle_lending", "erc4626_collateral_oracle", "amm_reserve_dependency", "vault_share_accounting"}) and candidate.impact_score >= 7


def build_graph_simulation_plan(ctx: TargetContext, candidate: FindingCandidate) -> dict:
    graph = getattr(ctx, "protocol_graph", None) or {}
    components = _graph_components(ctx)
    scenario = _pick_graph_scenario(graph, candidate)
    return {
        "schema": "bulk-audit-graph-sim/v1",
        "target": {"address": ctx.address, "chain": ctx.chain, "contract_name": ctx.contract_name},
        "candidate": {
            "detector": candidate.detector,
            "title": candidate.title,
            "bug_class": (candidate.evidence or {}).get("bug_class"),
            "affected_functions": candidate.affected_functions,
        },
        "scenario": scenario,
        "components": components,
        "steps": _scenario_steps(scenario, components),
        "assertions": _scenario_assertions(scenario),
        "notes": [
            "Generated from protocol graph resolved addresses; use as a fork validation harness, not a confirmed exploit.",
            "Fill in the target-specific action path where TODO-like comments are present in the Markdown plan.",
        ],
    }


def render_graph_simulation_markdown(plan: dict) -> str:
    lines = [
        "# Graph-Aware Fork Simulation Plan",
        "",
        f"Scenario: `{plan.get('scenario')}`",
        f"Target: `{((plan.get('target') or {}).get('contract_name') or (plan.get('target') or {}).get('address') or 'unknown')}`",
        "",
        "## Components",
    ]
    for component in plan.get("components") or []:
        lines.append(f"- `{component.get('role')}` `{component.get('label')}` `{component.get('address')}`")
    lines.extend(["", "## Steps"])
    for i, step in enumerate(plan.get("steps") or [], 1):
        lines.append(f"{i}. {step}")
    lines.extend(["", "## Assertions"])
    for assertion in plan.get("assertions") or []:
        lines.append(f"- {assertion}")
    lines.append("")
    return "\n".join(lines)


def build_graph_protocol_probe(target: str, components: list[dict], scenario: str) -> str:
    constants = []
    asserts = []
    for idx, component in enumerate(components[:12]):
        addr = component.get("address")
        if not addr or str(addr).lower() == str(target).lower():
            continue
        role = str(component.get("role") or "component").upper().replace("-", "_")
        constants.append(f"    address constant {role}_{idx} = {addr};")
        asserts.append(f'        require({role}_{idx}.code.length > 0, "{role}_{idx} has no code on fork");')
    return (_GRAPH_PROTOCOL_PROBE
            .replace("__TARGET__", target)
            .replace("__COMPONENT_CONSTANTS__", "\n".join(constants) or "    // no resolved companion constants")
            .replace("__COMPONENT_ASSERTS__", "\n".join(asserts) or "        // no resolved companion code assertions")
            .replace("__SCENARIO__", scenario.replace('"', "")))


def generate_graph_aware_simulation(
    ctx: TargetContext,
    candidate: FindingCandidate,
    sim_dir: Path,
    *,
    rpc_url: str,
    timeout: int,
) -> dict:
    if not is_graph_sim_eligible(ctx, candidate):
        return {"generated": False, "skipped": True, "note": "candidate has no resolved protocol group"}

    plan = build_graph_simulation_plan(ctx, candidate)
    sim_dir.mkdir(parents=True, exist_ok=True)
    (sim_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")
    (sim_dir / "test").mkdir(parents=True, exist_ok=True)
    (sim_dir / "src").mkdir(parents=True, exist_ok=True)
    (sim_dir / "graph_simulation.json").write_text(json.dumps(plan, indent=2, sort_keys=True, default=str), encoding="utf-8")
    (sim_dir / "graph_simulation.md").write_text(render_graph_simulation_markdown(plan), encoding="utf-8")
    probe = build_graph_protocol_probe(ctx.address, plan.get("components") or [], str(plan.get("scenario") or "protocol_group"))
    (sim_dir / "test" / "GraphProtocolProbe.t.sol").write_text(probe, encoding="utf-8")

    from ..runners.foundry_runner import run_forge_tests

    runner = run_forge_tests(
        sim_dir,
        sim_dir / "out_logs",
        rpc_url=rpc_url,
        timeout=timeout,
        match_path="test/GraphProtocolProbe.t.sol",
    )
    note = (
        f"graph-aware fork context probe: {runner.summary}; scenario={plan.get('scenario')}; "
        f"components={len(plan.get('components') or [])}"
    )
    return {
        "generated": True,
        "scaffold": True,
        "scenario": plan.get("scenario"),
        "components": plan.get("components") or [],
        "plan_path": str(sim_dir / "graph_simulation.json"),
        "markdown_path": str(sim_dir / "graph_simulation.md"),
        "runner": runner,
        "runner_status": runner.status,
        "note": note,
    }


def _graph_components(ctx: TargetContext) -> list[dict]:
    graph = getattr(ctx, "protocol_graph", None) or {}
    out = [{"role": "target", "label": ctx.contract_name or "target", "address": ctx.address, "source": "scan_target"}]
    seen = {str(ctx.address).lower()}
    for node in graph.get("nodes") or []:
        role = str(node.get("role") or "")
        addr = node.get("address")
        if role not in _GRAPH_SIM_ROLES or not addr:
            continue
        low = str(addr).lower()
        if low in seen:
            continue
        seen.add(low)
        out.append({
            "role": role,
            "label": node.get("label") or role,
            "address": str(addr),
            "source": node.get("source"),
            "confidence": node.get("confidence"),
        })
    return out[:16]


def _pick_graph_scenario(graph: dict, candidate: FindingCandidate) -> str:
    detector = str(candidate.detector or "")
    bug_class = str((candidate.evidence or {}).get("bug_class") or "")
    surface_ids = {str(surface.get("id") or "") for surface in graph.get("surfaces") or []}
    if detector == "economic_oracle_lending" or "oracle_lending" in surface_ids or bug_class == "erc4626_collateral_oracle":
        return "oracle_lending_bad_debt"
    if detector in {"erc4626_dual_asset_redeem_double_count", "vault_share_donation_inflation"} or "vault_share_accounting" in surface_ids:
        return "vault_redeem_share_accounting"
    if detector in {"amm_pair_reserve_desync", "hook_pair_burn_sync", "thin_liquidity_spot_oracle"} or "amm_reserve_dependency" in surface_ids:
        return "amm_reserve_manipulation"
    if "bridge_or_proof_domain" in surface_ids:
        return "bridge_or_proof_domain_binding"
    return "protocol_group_validation"


def _scenario_steps(scenario: str, components: list[dict]) -> list[str]:
    roles = {str(c.get("role")) for c in components}
    if scenario == "oracle_lending_bad_debt":
        return [
            "Read baseline oracle/exchange-rate output and lending liquidity/health from the resolved group.",
            "Perturb the mutable oracle/vault/pair component on a fork using donation, reserve skew, or stale price setup.",
            "Call the borrow/mint/redeem path on the market/controller at the manipulated valuation.",
            "Assert borrowed value exceeds healthy collateral value or protocol bad debt increases.",
        ]
    if scenario == "vault_redeem_share_accounting":
        return [
            "Read totalAssets, totalSupply, vault idle balances, and strategy/LP component balances.",
            "Donate or skew the non-primary asset/LP side, then deposit enough primary asset to own most shares.",
            "Redeem shares and compare all asset legs paid to the receiver against pre-redeem totalAssets.",
            "Assert value conservation across primary asset, non-asset leg, and LP position.",
        ]
    if scenario == "amm_reserve_manipulation":
        return [
            "Read pair reserves, token balances, and any target cached reserve/accounting state.",
            "Trigger the target path that burns/transfers/skims/syncs the pair or reads spot reserves.",
            "Swap or redeem against the desynced reserves in the same fork scenario.",
            "Assert paired-asset drain or reserve/accounting divergence.",
        ]
    if scenario == "bridge_or_proof_domain_binding":
        return [
            "Read verifier/messenger/receiver addresses and replay/nullifier storage slots.",
            "Replay the same payload/root/proof with altered domain, count, recipient, or gap-slot data.",
            "Assert receiver state/value changes only when all source-domain and proof-bound fields match.",
        ]
    return [
        f"Resolved roles available: {', '.join(sorted(roles))}.",
        "Build the fork action path across the resolved group, then assert value conservation or authorization binding.",
    ]


def _scenario_assertions(scenario: str) -> list[str]:
    if scenario == "oracle_lending_bad_debt":
        return ["reported collateral value cannot be moved by an unprivileged fork perturbation", "borrowed value must remain within healthy collateral bounds"]
    if scenario == "vault_redeem_share_accounting":
        return ["redeem must not pay the same LP/non-asset value twice", "share burn and asset payout must conserve vault value"]
    if scenario == "amm_reserve_manipulation":
        return ["pair reserve sync/skim/burn must not let token logic steal paired reserves", "spot reserve reads must be bounded by TWAP/liquidity guards"]
    if scenario == "bridge_or_proof_domain_binding":
        return ["message/proof/nullifier keys must bind source chain, sender, nonce, root, recipient, amount, and count", "gap slots must be constrained or zeroed"]
    return ["cross-contract state changes must preserve value and authorization invariants"]


def generate_and_run(
    ctx: TargetContext,
    candidate: FindingCandidate,
    sim_dir: Path,
    *,
    rpc_url: str,
    timeout: int,
) -> dict:
    """Build + run the manipulation probe. Returns a result dict.

    ``manipulable`` is True only when forge confirms the donation moved the price.
    """
    price_fn = _pick_price_view(ctx)
    token = _find_underlying_token(ctx)

    sim_dir.mkdir(parents=True, exist_ok=True)
    (sim_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")
    (sim_dir / "test").mkdir(parents=True, exist_ok=True)
    (sim_dir / "src").mkdir(parents=True, exist_ok=True)

    # If we can't identify a zero-arg price view AND an underlying token, we can't
    # auto-confirm — emit the flash-loan scaffold instead and be honest.
    if not price_fn or not token:
        src = build_flashloan_scaffold(ctx.address, price_fn)
        (sim_dir / "test" / "FlashLoanProbe.t.sol").write_text(src, encoding="utf-8")
        return {"generated": False, "manipulable": None, "scaffold": True,
                "note": f"scaffold only (price_view={price_fn}, token={token}); "
                        "complete the flash-loan TODO blocks to confirm"}

    from ..runners.foundry_runner import run_forge_tests

    src = build_donation_probe(ctx.address, token, price_fn)
    test_path = sim_dir / "test" / "OracleManipProbe.t.sol"
    test_path.write_text(src, encoding="utf-8")

    runner = run_forge_tests(
        sim_dir, sim_dir / "out_logs", rpc_url=rpc_url, timeout=timeout,
        match_path="test/OracleManipProbe.t.sol",
    )
    manipulable = runner.status == "ok" and runner.meta.get("tests_run", 0) >= 1
    note = (
        f"CONFIRMED: a donation to {ctx.address} moved {price_fn}() — unprivileged "
        "price manipulation"
        if manipulable else
        f"not confirmed: {price_fn}() did not move from a donation (likely oracle/"
        "internal-accounting based) or slot not found"
    )
    return {"generated": True, "manipulable": manipulable, "price_fn": price_fn,
            "token": token, "runner": runner, "runner_status": runner.status, "note": note}
