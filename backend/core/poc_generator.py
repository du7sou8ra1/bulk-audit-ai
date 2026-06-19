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
