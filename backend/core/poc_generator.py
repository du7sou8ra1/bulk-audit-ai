"""Auto-generate read-only Foundry fork PoCs for strong candidates.

SAFETY: a generated PoC only ever runs on a LOCAL fork (`forge test --fork-url`).
It uses the Foundry `Vm` cheatcode interface (vm.prank / vm.load) — NEVER
vm.broadcast, private keys, or cast send (the foundry_runner also refuses any
file containing those tokens). Executing the candidate exploit against a local
fork is explicitly allowed and is what upgrades a candidate to "confirmed".

A PoC asks one honest question: *can an unprivileged attacker successfully
invoke this privileged selector?* If forge reports the call succeeded
(`passed = True`), that is real evidence of a missing-auth path. A failure is
treated as INCONCLUSIVE (it may simply mean access control blocked the call),
so it never raises confidence.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..detectors.base import FindingCandidate, TargetContext, is_externally_callable
from .proxy_resolver import IMPL_SLOT
from .scoring import ScoreResult

logger = logging.getLogger("bulkauditai.poc")

ATTACKER = "address(uint160(0xA11CE))"

# Detectors for which we know how to build a meaningful unauthorized-call PoC.
_POC_DETECTORS = {"proxy_upgrade", "arbitrary_call", "governance_blast_radius"}
# Upgrade-like functions get an extra "implementation slot changed" assertion.
_UPGRADE_FUNCS = {
    "upgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "upgradeAndCall",
    "setImplementation",
    "changeImplementation",
}


def is_poc_eligible(candidate: FindingCandidate, score: ScoreResult) -> bool:
    if candidate.detector not in _POC_DETECTORS:
        return False
    # Don't waste a fork run on findings that are already governance/info.
    ev = candidate.evidence or {}
    if ev.get("governance_controlled") or ev.get("has_access_control"):
        return False
    return score.impact_score >= 7 and score.confidence_score >= 4


def _normalize_type(t: str) -> str | None:
    """Canonicalize a Solidity elementary type, or None if unsupported."""
    t = t.strip()
    # Drop data-location / keyword noise that may have leaked in.
    t = re.sub(r"\b(calldata|memory|storage)\b", "", t).strip()
    if not t or "[" in t or "(" in t:  # arrays / tuples / structs unsupported
        return None
    if t == "uint":
        return "uint256"
    if t == "int":
        return "int256"
    if t == "address" or t == "bool" or t == "string" or t == "bytes":
        return t
    if re.fullmatch(r"uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)", t):
        return t
    if re.fullmatch(r"int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)", t):
        return t
    if re.fullmatch(r"bytes([1-9]|[12][0-9]|3[0-2])", t):
        return t
    return None  # contract/enum/struct types — skip for safety


def _literal_for(t: str) -> str:
    if t == "address":
        return "address(uint160(0xBEEF))"
    if t == "bool":
        return "false"
    if t == "string":
        return '""'
    if t == "bytes":
        return 'hex""'
    if t.startswith("bytes"):
        return f"{t}(0)"
    if t.startswith("uint"):
        return f"{t}(0)"
    if t.startswith("int"):
        return f"{t}(0)"
    return "0"


def _parse_param_types(params: str) -> list[str] | None:
    """Return canonical types for each param, or None if any is unsupported."""
    params = (params or "").strip()
    if not params:
        return []
    out: list[str] = []
    for chunk in params.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        first = chunk.split()[0]
        norm = _normalize_type(first)
        if norm is None:
            return None
        out.append(norm)
    return out


def _find_function(ctx: TargetContext, name: str):
    for fn in ctx.functions():
        if fn.name == name:
            return fn
    return None


def build_poc_source(
    target_address: str, fn_name: str, param_types: list[str], is_upgrade: bool
) -> str:
    sig = f"{fn_name}({','.join(param_types)})"
    args = ", ".join(_literal_for(t) for t in param_types)
    encode = (
        f'abi.encodeWithSignature("{sig}"{(", " + args) if args else ""})'
    )
    slot_check = ""
    if is_upgrade:
        slot_check = f"""
        bytes32 implBefore = vm.load(TARGET, bytes32(uint256({hex(IMPL_SLOT)})));"""
    post_check = ""
    if is_upgrade:
        post_check = f"""
        bytes32 implAfter = vm.load(TARGET, bytes32(uint256({hex(IMPL_SLOT)})));
        require(implAfter != implBefore, "impl slot unchanged");"""

    return f"""// SPDX-License-Identifier: MIT
// AUTO-GENERATED READ-ONLY FORK PoC — runs only on a local fork. DO NOT BROADCAST.
// Question: can an unprivileged caller invoke `{sig}` on the target?
pragma solidity ^0.8.19;

interface Vm {{
    function prank(address) external;
    function load(address target, bytes32 slot) external view returns (bytes32);
    function label(address account, string calldata newLabel) external;
}}

contract PocTest {{
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    address internal constant TARGET = {target_address};

    function test_unauthorized_{fn_name}() external {{
        uint256 size;
        address t = TARGET;
        assembly {{ size := extcodesize(t) }}
        require(size > 0, "no code on fork");
{slot_check}
        bytes memory cd = {encode};
        vm.prank({ATTACKER});
        (bool ok, ) = TARGET.call(cd);
        require(ok, "call reverted (likely access-controlled or invalid args) - inconclusive");
{post_check}
    }}
}}
"""


def _foundry_toml() -> str:
    # ffi explicitly disabled + no fs permissions: the PoC cannot shell out or
    # touch the filesystem, only read the local fork.
    return (
        "[profile.default]\n"
        "src = 'src'\n"
        "out = 'out'\n"
        "test = 'test'\n"
        "libs = []\n"
        "ffi = false\n"
        "fs_permissions = []\n"
    )


def generate_poc(
    ctx: TargetContext, candidate: FindingCandidate, foundry_dir: Path
) -> dict | None:
    """Render a PoC project. Returns metadata or None if not generatable."""
    fn_name = (candidate.affected_functions or [None])[0]
    if not fn_name:
        return None

    # SAFETY/CORRECTNESS GATE: only generate a PoC for a real, externally
    # callable function declared in source. This rejects role names (e.g.
    # DEFAULT_ADMIN_ROLE from the governance detector) and other non-callables,
    # which would otherwise produce a meaningless PoC that calls a view getter
    # and falsely "confirms" the finding.
    fn = _find_function(ctx, fn_name)
    if fn is None:
        return {"skipped": True, "reason": f"'{fn_name}' is not a function declared in source"}
    if not is_externally_callable(fn):
        return {"skipped": True, "reason": f"'{fn_name}' is not externally callable"}

    param_types = _parse_param_types(fn.params)
    if param_types is None:
        return {"skipped": True, "reason": f"unsupported parameter types in {fn_name}({fn.params})"}

    is_upgrade = fn_name in _UPGRADE_FUNCS
    src = build_poc_source(ctx.address, fn_name, param_types, is_upgrade)

    (foundry_dir / "test").mkdir(parents=True, exist_ok=True)
    (foundry_dir / "src").mkdir(parents=True, exist_ok=True)
    (foundry_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")
    test_path = foundry_dir / "test" / "Poc.t.sol"
    test_path.write_text(src, encoding="utf-8")

    return {
        "skipped": False,
        "test_path": str(test_path),
        "signature": f"{fn_name}({','.join(param_types)})",
        "is_upgrade": is_upgrade,
    }


def generate_and_run(
    ctx: TargetContext,
    candidate: FindingCandidate,
    foundry_dir: Path,
    *,
    rpc_url: str,
    timeout: int,
) -> dict:
    """Generate a PoC and run it on a local fork. Returns a result dict.

    ``passed`` is True only when forge confirms the unprivileged call succeeded.
    """
    from ..runners.foundry_runner import run_forge_tests

    meta = generate_poc(ctx, candidate, foundry_dir)
    if meta is None:
        return {"generated": False, "passed": None, "note": "no eligible function"}
    if meta.get("skipped"):
        return {"generated": False, "passed": None, "note": meta.get("reason", "skipped")}

    runner = run_forge_tests(
        foundry_dir,
        foundry_dir / "out_logs",
        rpc_url=rpc_url,
        timeout=timeout,
        match_path="test/Poc.t.sol",
    )
    # `passed` is True only when forge confirms our test actually ran and
    # succeeded (run_forge_tests treats zero-tests-executed as failed).
    passed = runner.status == "ok" and runner.meta.get("tests_run", 0) >= 1
    note = (
        f"unprivileged call to {meta['signature']} SUCCEEDED on fork"
        if passed
        else f"PoC inconclusive ({runner.status}): call did not succeed for an unprivileged caller"
    )
    return {
        "generated": True,
        "passed": passed,
        "signature": meta["signature"],
        "is_upgrade": meta["is_upgrade"],
        "test_path": meta["test_path"],
        "runner_status": runner.status,
        "runner": runner,
        "note": note,
    }


# --------------------------------------------------------------------------- #
# State-invariant PoC scaffold (gap #2)
# --------------------------------------------------------------------------- #
# Most real criticals (accounting, settlement binding, rounding, double-spend)
# are NOT "unguarded selector" bugs — they need a MULTI-STEP state PoC that
# asserts an invariant break (attacker gained value without equivalent deposit).
# Auto-generating a *correct* exploit is protocol-specific and hard, so for these
# bug classes we emit a compiling SCAFFOLD with the setup/attack/assert skeleton
# and TODO markers — far more actionable than the call-succeeds PoC, and honest
# (it is written to evidence, never counted as a passing PoC).
_WEIRD_HUNT_POC_TEMPLATES = {
    "actual_received_accounting": [
        "Use a fee-on-transfer or rebasing token mock as the deposited asset.",
        "Compare shares/credits minted from nominal amount versus balanceBefore/balanceAfter delta.",
    ],
    "merkle_claim_binding": [
        "Reuse one Merkle proof while mutating recipient, amount, token/domain, or claim index.",
        "Assert the same proof cannot move value under any changed field.",
    ],
    "bitmap_claim_collision": [
        "Claim indexes separated by 256 or above the truncated width.",
        "Assert both indexes cannot map to the same bitmap bit or bypass the claimed marker.",
    ],
    "bridge_replay_key": [
        "Replay the same payload with changed source chain, sender/peer, nonce/message id, or destination.",
        "Assert the processed key rejects every domain mutation before value moves.",
    ],
    "address_alias_bridge": [
        "Test both aliased and unaliased L1/L2 sender forms for the target rollup.",
        "Assert only the canonical bridge peer can finalize/mint/unlock.",
    ],
    "oracle_freshness_sequencer": [
        "Mock stale, zero/negative, answeredInRound-lagged, and sequencer-down oracle responses.",
        "Assert borrow/mint/withdraw/liquidation value paths revert under every bad response.",
    ],
    "twap_observation_cardinality": [
        "Fork a low-cardinality/low-liquidity pool and force period=0 or a very short TWAP window.",
        "Assert one-block price movement cannot change mint/borrow/withdraw output beyond tolerance.",
    ],
    "forced_eth_accounting": [
        "Force ETH into the contract before share/reward/solvency math using a selfdestruct helper.",
        "Assert internal accounting, not address(this).balance, controls user redeemable value.",
    ],
    "create2_metamorphic_trust": [
        "Allowlist/check a CREATE2 address before deployment, then deploy unexpected runtime code if possible.",
        "Assert runtime code hash is validated before trust, delegatecall, or asset movement.",
    ],
    "trycatch_finalization": [
        "Make the downstream external call revert inside the try block.",
        "Assert processed/consumed/finalized state is not set, or the message remains retryable.",
    ],
    "reward_debt_order": [
        "Use a malicious reward token or receiver callback to reenter claim/harvest before debt update.",
        "Assert total rewards paid cannot exceed accrued rewards after reentrancy.",
    ],
    "accumulator_zero_supply": [
        "Inject rewards while total supply/shares is zero, then let the first depositor claim.",
        "Assert rewards are either queued safely or distributed without loss/overallocation.",
    ],
    "position_merge_split": [
        "Create a position with debt/collateral/reward state, then split/merge/transfer it.",
        "Assert source and destination totals equal the pre-operation invariant.",
    ],
    "governance_snapshot_bypass": [
        "Borrow or transfer voting power in the same transaction/block as vote or execute.",
        "Assert voting power comes from a prior snapshot/checkpoint, not current balance.",
    ],
    "pausability_bypass": [
        "Pause the protocol, then reach the same value sink through alternate entrypoints or multicall.",
        "Assert every path to the paused sink reverts while paused.",
    ],
    "multicall_state_cache": [
        "Call the same payable/value-crediting inner function twice through multicall with one msg.value.",
        "Assert msg.value or cached balance is consumed exactly once.",
    ],
    "wad_ray_unit_mismatch": [
        "Run the formula against 6, 18, and 27 decimal assets and compare to a high-precision model.",
        "Assert all conversions normalize before multiplication/division.",
    ],
    "duplicate_batch_item": [
        "Submit duplicate ids/tokens/messages in one batch.",
        "Assert duplicates are rejected or counted exactly once before any value mutation.",
    ],
    "cross_function_value_flow": [
        "Mutate the calldata field that taint analysis says reaches the internal value sink.",
        "Assert destination and amount cannot be attacker-selected beyond the intended invariant.",
    ],
    "privacy_pool_nullifier_ordering": [
        "Use a receiver/token hook to reenter before the nullifier/spent marker is written.",
        "Assert the same proof/nullifier cannot withdraw or claim twice.",
    ],
    "privacy_pool_public_input_binding": [
        "Mutate recipient, amount, fee, relayer, root, or nullifier while reusing the proof commitment.",
        "Assert the verifier/public-input layout rejects every changed value.",
    ],
    "proof-to-value-binding": [
        "Trace every value transferred by the helper path back to a proof-bound public input.",
        "Assert mutating the flagged value while keeping the proof fixed reverts.",
    ],
}

_STATE_INVARIANT_CLASSES = {
    "share_accounting", "settlement_binding", "replay", "decimal", "oracle", "reentrancy",
    *set(_WEIRD_HUNT_POC_TEMPLATES),
}


def is_state_invariant_finding(candidate: FindingCandidate) -> bool:
    ev = candidate.evidence or {}
    if ev.get("needs_stateful_poc"):
        return True
    return str(ev.get("bug_class", "")) in _STATE_INVARIANT_CLASSES


def _state_template_comments(bug_class: str) -> str:
    items = _WEIRD_HUNT_POC_TEMPLATES.get(bug_class, [])
    if not items:
        return "// Template checklist: choose setup/attack/assert steps for this invariant family."
    lines = ["// Template checklist:"]
    lines.extend(f"// - {item}" for item in items)
    return "\n".join(lines)


def build_state_invariant_scaffold(
    target_address: str, fn_name: str | None, bug_class: str
) -> str:
    fn = fn_name or "targetFunction"
    template_comments = _state_template_comments(bug_class)
    return f"""// SPDX-License-Identifier: MIT
// AUTO-GENERATED STATE-INVARIANT PoC *SCAFFOLD* — bug class: {bug_class}
// Runs only on a local fork. DO NOT BROADCAST. This is a SKELETON: complete the
// three TODO blocks. It is NOT counted as a passing PoC until you make the
// invariant assertion hold against the real exploit.
{template_comments}
pragma solidity ^0.8.19;

interface Vm {{
    function prank(address) external;
    function deal(address, uint256) external;
    function store(address, bytes32, bytes32) external;
    function load(address, bytes32) external view returns (bytes32);
    function createSelectFork(string calldata) external returns (uint256);
}}
interface ITarget {{
    // TODO: declare the functions you need, e.g.:
    // function {fn}(/* args */) external;
    // function balanceOf(address) external view returns (uint256);
    // function totalAssets() external view returns (uint256);
}}

contract StateInvariantPoc {{
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    address internal constant TARGET = {target_address};
    address internal constant ATTACKER = address(uint160(0xA11CE));

    function test_invariant_break_{fn}() external {{
        // 1) SETUP — seed attacker balances / approvals on the fork.
        vm.deal(ATTACKER, 100 ether);
        // TODO: vm.store(TARGET, <slot>, <value>) or deposit to reach a realistic state.
        uint256 before = _attackerValue();

        // 2) ATTACK — perform the candidate exploit as ATTACKER.
        vm.prank(ATTACKER);
        // TODO: ITarget(TARGET).{fn}(/* crafted args */);

        // 3) ASSERT THE INVARIANT BREAK — gained value with no equivalent input.
        uint256 afterv = _attackerValue();
        require(afterv > before, "no value extracted - candidate likely safe");
        // For accounting bugs also assert protocol solvency broke, e.g.:
        // require(ITarget(TARGET).totalAssets() < realBackedValue, "accounting intact");
    }}

    function _attackerValue() internal view returns (uint256) {{
        // TODO: sum the assets the attacker can redeem/withdraw.
        return ATTACKER.balance;
    }}
}}
"""


def write_state_scaffold(
    ctx: TargetContext, candidate: FindingCandidate, foundry_dir: Path
) -> dict:
    """Write a compiling state-invariant PoC scaffold to the workspace (not run)."""
    fn = (candidate.affected_functions or [None])[0]
    bug_class = str((candidate.evidence or {}).get("bug_class", "accounting"))
    src = build_state_invariant_scaffold(ctx.address, fn, bug_class)
    (foundry_dir / "test").mkdir(parents=True, exist_ok=True)
    (foundry_dir / "src").mkdir(parents=True, exist_ok=True)
    (foundry_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")
    path = foundry_dir / "test" / "StateInvariantPoc.t.sol"
    path.write_text(src, encoding="utf-8")
    return {"scaffold": True, "path": str(path), "bug_class": bug_class,
            "note": "state-invariant PoC scaffold written — complete the TODO blocks to confirm"}
