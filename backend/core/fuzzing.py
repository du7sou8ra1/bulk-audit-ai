"""Fuzz-readiness checks and starter Foundry fuzz-suite generation.

Phase 1/2 scope:
  * detect existing Foundry/Echidna/Medusa/Halmos fuzz assets,
  * run existing Foundry fuzz/invariant tests when the target workspace is a
    real Foundry project,
  * generate a standalone Foundry starter suite from ABI/source signals.

The generated suite is scaffolding, not proof. It is saved for the auditor and
validated with `forge test --list` when forge is installed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..detectors.base import TargetContext
from ..runners.base import RunnerResult
from .command_runner import run_command, which


FUZZ_TEST_RE = re.compile(r"\b(testFuzz\w*|invariant_\w*|statefulFuzz\w*)\b")
ECHIDNA_RE = re.compile(r"\bechidna_\w+\s*\(")

SURFACE_RULES: list[tuple[str, re.Pattern, list[str]]] = [
    (
        "vault/share accounting",
        re.compile(r"deposit|withdraw|redeem|mint|shares?|totalAssets|convertToShares", re.I),
        [
            "assets held by the vault should cover all redeemable shares",
            "deposit->withdraw round trips should not create profit except documented fees",
            "direct token donations should not inflate later depositor losses",
        ],
    ),
    (
        "lending solvency",
        re.compile(r"borrow|repay|liquidat|collateral|health|debt|reserve", re.I),
        [
            "a borrower should not increase debt or withdraw collateral while unhealthy",
            "donations/reserve mutations should not bypass health checks",
            "liquidation should reduce bad debt and never create free collateral",
        ],
    ),
    (
        "AMM/oracle math",
        re.compile(r"swap|getReserves|slot0|price|oracle|sqrtP|tick|liquidity", re.I),
        [
            "price output should remain bounded under one-block reserve skew",
            "swap steps around tick boundaries should cross liquidity exactly once",
            "rounding should favor the pool on exits and exact-output paths",
        ],
    ),
    (
        "rewards/checkpoints",
        re.compile(r"claim|reward|checkpoint|royalt|settle|record|cumulative", re.I),
        [
            "claimable rewards should never exceed deposited/earned rewards",
            "zero-value transfers should not append new reward checkpoints",
            "repeated settle/claim calls in one epoch should be idempotent",
        ],
    ),
    (
        "bridge/proof replay",
        re.compile(r"bridge|root|proof|message|relay|nonce|domain|verifier", re.I),
        [
            "each message/root/nonce can be consumed at most once",
            "source chain, destination chain, sender, receiver, and nonce are domain-bound",
            "zero/unset roots and untrusted verifiers should never authorize value movement",
        ],
    ),
    (
        "token/allowance flows",
        re.compile(r"transferFrom|approve|permit|allowance|transfer|safeTransfer", re.I),
        [
            "caller-supplied from addresses must be msg.sender-bound or authorized",
            "zero-amount transfers should not unlock paid/rewarded paths",
            "allowances should not be drainable through arbitrary target+calldata routers",
        ],
    ),
]

SUPPORTED_ABI_TYPES = {
    "address": "address",
    "bool": "bool",
    "bytes": "bytes memory",
    "string": "string memory",
    "bytes32": "bytes32",
}


@dataclass
class GeneratedSuite:
    project_dir: Path
    test_path: Path
    plan_path: Path
    fuzz_tests: int
    skipped_functions: list[str] = field(default_factory=list)
    surfaces: list[str] = field(default_factory=list)


def inspect_fuzz_readiness(source_dir: Path, source_files: dict[str, str]) -> dict:
    """Return a compact inventory of existing fuzz assets."""
    sol_tests = list(source_dir.rglob("*.t.sol")) if source_dir.exists() else []
    all_text = "\n".join(source_files.values())

    foundry_toml = source_dir / "foundry.toml"
    hardhat_config = any((source_dir / name).exists() for name in ("hardhat.config.ts", "hardhat.config.js"))
    echidna_configs = [
        str(p.relative_to(source_dir))
        for p in source_dir.rglob("*")
        if p.is_file() and p.name.lower() in {"echidna.yaml", "echidna.yml", "echidna.config.yaml"}
    ] if source_dir.exists() else []
    medusa_configs = [
        str(p.relative_to(source_dir))
        for p in source_dir.rglob("*")
        if p.is_file() and p.name.lower() in {"medusa.json", "medusa.yaml", "medusa.yml"}
    ] if source_dir.exists() else []
    halmos_configs = [
        str(p.relative_to(source_dir))
        for p in source_dir.rglob("*")
        if p.is_file() and p.name.lower() in {"halmos.toml", "halmos.config.toml"}
    ] if source_dir.exists() else []

    fuzz_files: list[str] = []
    invariant_files: list[str] = []
    for p in sol_tests:
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if FUZZ_TEST_RE.search(txt):
            fuzz_files.append(str(p.relative_to(source_dir)))
        if re.search(r"\binvariant_\w+\s*\(", txt):
            invariant_files.append(str(p.relative_to(source_dir)))

    echidna_properties = len(ECHIDNA_RE.findall(all_text))
    surfaces = infer_surfaces(all_text)
    return {
        "foundry_project": foundry_toml.exists(),
        "hardhat_project": hardhat_config,
        "foundry_fuzz_files": fuzz_files,
        "foundry_invariant_files": invariant_files,
        "echidna_configs": echidna_configs,
        "echidna_properties": echidna_properties,
        "medusa_configs": medusa_configs,
        "halmos_configs": halmos_configs,
        "surfaces": surfaces,
        "recommended_next": _recommended_next(surfaces, bool(fuzz_files or invariant_files or echidna_properties)),
    }


def infer_surfaces(text: str) -> list[str]:
    surfaces = [name for name, pat, _ideas in SURFACE_RULES if pat.search(text or "")]
    return surfaces or ["generic external-call state machine"]


def _recommended_next(surfaces: list[str], has_existing: bool) -> list[str]:
    out: list[str] = []
    if has_existing:
        out.append("run existing fuzz/invariant suite and inspect failures/timeouts")
    else:
        out.append("review generated Foundry starter suite and replace smoke checks with protocol-specific invariants")
    for name, _pat, ideas in SURFACE_RULES:
        if name in surfaces:
            out.extend(ideas[:2])
    return out[:8]


def run_fuzzing(
    ctx: TargetContext,
    *,
    source_dir: Path,
    out_dir: Path,
    timeout: int = 180,
) -> RunnerResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    readiness = inspect_fuzz_readiness(source_dir, ctx.source_files)
    (out_dir / "fuzz_readiness.json").write_text(
        json.dumps(readiness, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    existing = _run_existing_foundry_fuzz(source_dir, out_dir / "existing_foundry", timeout=timeout)
    existing_echidna = _run_existing_echidna_fuzz(
        source_dir, readiness, out_dir / "existing_echidna", timeout=timeout
    )
    existing_medusa = _run_existing_medusa_fuzz(
        source_dir, readiness, out_dir / "existing_medusa", timeout=timeout
    )
    generated = generate_foundry_starter_suite(ctx, out_dir / "generated_foundry", readiness=readiness)
    generated_validation = _validate_generated_suite(generated.project_dir, out_dir / "generated_validation", timeout=timeout)

    summary = (
        f"fuzz readiness: surfaces={', '.join(readiness['surfaces'])}; "
        f"existing_foundry={existing.status}; existing_echidna={existing_echidna.status}; "
        f"existing_medusa={existing_medusa.status}; generated_foundry={generated.fuzz_tests} fuzz test(s); "
        f"path={generated.project_dir}"
    )
    if generated_validation.status not in {"ok", "skipped"}:
        summary += f"; generated validation={generated_validation.status}"

    result = RunnerResult(
        tool_name="fuzzing",
        status="ok",
        command=generated_validation.command or existing.command,
        exit_code=generated_validation.exit_code,
        timed_out=generated_validation.timed_out,
        stdout_path=generated_validation.stdout_path,
        stderr_path=generated_validation.stderr_path,
        summary=summary,
        findings=[],
        meta={
            "readiness": readiness,
            "generated_project": str(generated.project_dir),
            "generated_test": str(generated.test_path),
            "generated_plan": str(generated.plan_path),
            "generated_fuzz_tests": generated.fuzz_tests,
            "skipped_functions": generated.skipped_functions,
            "existing_foundry": {
                "status": existing.status,
                "summary": existing.summary,
                "command": existing.command,
                "stdout_path": existing.stdout_path,
                "stderr_path": existing.stderr_path,
            },
            "existing_echidna": {
                "status": existing_echidna.status,
                "summary": existing_echidna.summary,
                "command": existing_echidna.command,
                "stdout_path": existing_echidna.stdout_path,
                "stderr_path": existing_echidna.stderr_path,
            },
            "existing_medusa": {
                "status": existing_medusa.status,
                "summary": existing_medusa.summary,
                "command": existing_medusa.command,
                "stdout_path": existing_medusa.stdout_path,
                "stderr_path": existing_medusa.stderr_path,
            },
            "generated_validation": {
                "status": generated_validation.status,
                "summary": generated_validation.summary,
                "command": generated_validation.command,
                "stdout_path": generated_validation.stdout_path,
                "stderr_path": generated_validation.stderr_path,
            },
        },
    )
    failing_existing = next(
        (r for r in (existing, existing_echidna, existing_medusa) if r.status in {"failed", "timeout"}),
        None,
    )
    if failing_existing is not None:
        existing = failing_existing
        result.status = existing.status
        result.summary = f"existing {existing.tool_name} suite {existing.status}: {existing.summary}"
        result.command = existing.command
        result.exit_code = existing.exit_code
        result.timed_out = existing.timed_out
        result.stdout_path = existing.stdout_path
        result.stderr_path = existing.stderr_path
    elif generated_validation.status == "failed":
        result.status = "failed"
        result.summary = f"generated fuzz suite did not compile/list cleanly: {generated_validation.summary}"
        result.command = generated_validation.command
        result.exit_code = generated_validation.exit_code
        result.stdout_path = generated_validation.stdout_path
        result.stderr_path = generated_validation.stderr_path
    summary_path = out_dir / "fuzz_summary.json"
    summary_path.write_text(json.dumps(result.meta, indent=2, sort_keys=True, default=str), encoding="utf-8")
    result.json_output_path = str(summary_path)
    return result


def _run_existing_foundry_fuzz(source_dir: Path, out_dir: Path, *, timeout: int) -> RunnerResult:
    if not (source_dir / "foundry.toml").exists():
        return RunnerResult.skipped("foundry-fuzz", "no foundry.toml in fetched/source workspace")
    if which("forge") is None:
        return RunnerResult.skipped("foundry-fuzz", "forge not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = run_command(
        ["forge", "test", "--json", "--match-test", "(testFuzz|invariant_)"],
        cwd=source_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="forge_fuzz",
    )
    res = RunnerResult.from_command("foundry-fuzz", cmd)
    if res.status == "ok":
        res.summary = "existing Foundry fuzz/invariant suite ran"
    elif res.status == "failed":
        res.summary = "existing Foundry fuzz/invariant suite failed"
    elif res.status == "timeout":
        res.summary = "existing Foundry fuzz/invariant suite timed out"
    return res


def _run_existing_echidna_fuzz(
    source_dir: Path, readiness: dict, out_dir: Path, *, timeout: int
) -> RunnerResult:
    configs = readiness.get("echidna_configs") or []
    has_properties = bool(readiness.get("echidna_properties"))
    if not configs and not has_properties:
        return RunnerResult.skipped("echidna-fuzz", "no echidna config/properties detected")
    exe = "echidna" if which("echidna") else "echidna-test" if which("echidna-test") else ""
    if not exe:
        return RunnerResult.skipped("echidna-fuzz", "echidna not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    args = [exe, "."]
    if configs:
        args += ["--config", configs[0]]
    cmd = run_command(
        args,
        cwd=source_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="echidna_fuzz",
    )
    res = RunnerResult.from_command("echidna-fuzz", cmd)
    res.summary = "existing Echidna campaign ran" if res.status == "ok" else f"existing Echidna campaign {res.status}"
    return res


def _run_existing_medusa_fuzz(
    source_dir: Path, readiness: dict, out_dir: Path, *, timeout: int
) -> RunnerResult:
    configs = readiness.get("medusa_configs") or []
    if not configs:
        return RunnerResult.skipped("medusa-fuzz", "no medusa config detected")
    if which("medusa") is None:
        return RunnerResult.skipped("medusa-fuzz", "medusa not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = run_command(
        ["medusa", "fuzz", "--config", configs[0], "--no-color"],
        cwd=source_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="medusa_fuzz",
    )
    res = RunnerResult.from_command("medusa-fuzz", cmd)
    res.summary = "existing Medusa campaign ran" if res.status == "ok" else f"existing Medusa campaign {res.status}"
    return res


def _validate_generated_suite(project_dir: Path, out_dir: Path, *, timeout: int) -> RunnerResult:
    if which("forge") is None:
        return RunnerResult.skipped("generated-foundry-fuzz", "forge not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = run_command(
        ["forge", "test", "--list"],
        cwd=project_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="forge_generated_list",
    )
    res = RunnerResult.from_command("generated-foundry-fuzz", cmd)
    res.summary = "generated Foundry suite listed successfully" if res.status == "ok" else "generated Foundry suite failed to list"
    return res


def generate_foundry_starter_suite(
    ctx: TargetContext,
    out_dir: Path,
    *,
    readiness: dict | None = None,
    max_functions: int = 18,
) -> GeneratedSuite:
    project_dir = out_dir
    test_dir = project_dir / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "src").mkdir(parents=True, exist_ok=True)
    (project_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")

    abi_functions = _abi_functions(ctx.abi)
    generated: list[str] = []
    skipped: list[str] = []
    for idx, fn in enumerate(abi_functions):
        if len(generated) >= max_functions:
            skipped.append(f"{fn['name']} (cap reached)")
            continue
        maybe = _render_fuzz_function(idx, fn)
        if maybe:
            generated.append(maybe)
        else:
            skipped.append(_signature(fn))

    surfaces = (readiness or {}).get("surfaces") or infer_surfaces(ctx.all_source_text())
    test_path = test_dir / "BulkAuditGeneratedFuzz.t.sol"
    test_path.write_text(_render_foundry_test(ctx.address, generated), encoding="utf-8")
    plan_path = project_dir / "FUZZ_PLAN.md"
    plan_path.write_text(_render_fuzz_plan(ctx, surfaces, generated, skipped), encoding="utf-8")
    return GeneratedSuite(
        project_dir=project_dir,
        test_path=test_path,
        plan_path=plan_path,
        fuzz_tests=len(generated),
        skipped_functions=skipped,
        surfaces=surfaces,
    )


def _foundry_toml() -> str:
    return """[profile.default]
src = "src"
test = "test"
out = "out"
libs = []
solc_version = "0.8.23"
optimizer = true
optimizer_runs = 200
fuzz = { runs = 128 }
invariant = { runs = 32, depth = 16 }
ffi = false
"""


def _abi_functions(abi: list | dict | None) -> list[dict]:
    items = abi if isinstance(abi, list) else []
    out = []
    for item in items:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        state = item.get("stateMutability") or ""
        name = item.get("name") or ""
        if not name or state in {"view", "pure"}:
            continue
        out.append(item)
    risk_order = ("claim", "withdraw", "redeem", "mint", "deposit", "borrow", "repay", "liquidat", "transfer", "approve", "permit", "execute", "relay", "process")
    return sorted(
        out,
        key=lambda f: min((i for i, pat in enumerate(risk_order) if pat in (f.get("name") or "").lower()), default=999),
    )


def _sol_type(abi_type: str) -> str | None:
    t = abi_type or ""
    if t in SUPPORTED_ABI_TYPES:
        return SUPPORTED_ABI_TYPES[t]
    if re.fullmatch(r"uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", t):
        return t
    if re.fullmatch(r"int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", t):
        return t
    if re.fullmatch(r"bytes([1-9]|[12][0-9]|3[0-2])", t):
        return t
    return None


def _render_fuzz_function(index: int, fn: dict) -> str | None:
    inputs = fn.get("inputs") or []
    if len(inputs) > 5:
        return None
    types: list[str] = []
    params: list[str] = []
    args: list[str] = []
    for i, inp in enumerate(inputs):
        abi_type = str(inp.get("type") or "")
        sol_type = _sol_type(abi_type)
        if sol_type is None:
            return None
        name = _safe_param_name(inp.get("name") or f"arg{i}", i)
        types.append(abi_type)
        params.append(f"{sol_type} {name}")
        args.append(name)
    sig = _signature(fn)
    safe_name = _safe_identifier(fn.get("name") or "fn")
    params_blob = ", ".join(params)
    args_blob = (", " + ", ".join(args)) if args else ""
    return f"""
    function testFuzz_{safe_name}_{index}({params_blob}) public {{
        _call(abi.encodeWithSelector(bytes4(keccak256(bytes("{sig}"))){args_blob}));
    }}
"""


def _signature(fn: dict) -> str:
    inputs = fn.get("inputs") or []
    types = ",".join(str(i.get("type") or "") for i in inputs if isinstance(i, dict))
    return f"{fn.get('name', '')}({types})"


def _safe_param_name(raw: str, index: int) -> str:
    name = _safe_identifier(raw or f"arg{index}")
    if name in {"from", "to", "value", "selector", "target"}:
        name = f"{name}_arg"
    return name or f"arg{index}"


def _safe_identifier(raw: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", raw or "")
    if not name or name[0].isdigit():
        name = f"arg_{name}"
    return name[:64]


def _render_foundry_test(address: str, functions: list[str]) -> str:
    target_literal = _address_literal(address)
    body = "\n".join(functions) if functions else """
    function testFuzz_rawCalldata(bytes calldata data) public {
        _call(data);
    }
"""
    return f"""// SPDX-License-Identifier: MIT
// AUTO-GENERATED by BulkAuditAI fuzzing phase 1/2.
// This is a starter suite. Reverts are recorded but not treated as failures
// because live fork state, roles, and balances may legitimately block calls.
pragma solidity ^0.8.23;

contract BulkAuditGeneratedFuzz {{
    address internal constant TARGET = {target_literal};
    uint256 public calls;
    uint256 public successes;

    event FuzzCall(bytes data, bool ok, bytes ret);

    receive() external payable {{}}

    function test_target_has_code() public view {{
        require(TARGET.code.length > 0, "target has no code; run on a fork or replace TARGET");
    }}

    function invariant_target_code_persists() public view {{
        require(TARGET.code.length > 0, "target code disappeared");
    }}

    function _call(bytes memory data) internal {{
        calls++;
        (bool ok, bytes memory ret) = TARGET.call(data);
        if (ok) successes++;
        emit FuzzCall(data, ok, ret);
    }}
{body}
}}
"""


def _address_literal(address: str) -> str:
    addr = (address or "").strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", addr):
        return f"address(uint160({addr}))"
    return "address(0)"


def _render_fuzz_plan(ctx: TargetContext, surfaces: list[str], generated: list[str], skipped: list[str]) -> str:
    ideas: list[str] = []
    for name, _pat, surface_ideas in SURFACE_RULES:
        if name in surfaces:
            ideas.extend(surface_ideas)
    if not ideas:
        ideas = [
            "define value-conservation invariants for every asset the contract can custody",
            "model an unprivileged attacker and at least two honest users",
            "add sequence tests for every deposit/mutate/withdraw lifecycle",
        ]

    bullets = "\n".join(f"- {idea}" for idea in dict.fromkeys(ideas))
    skipped_blob = "\n".join(f"- {s}" for s in skipped[:30]) or "- none"
    return f"""# BulkAuditAI Fuzz Plan

Target: `{ctx.address}`
Chain: `{ctx.chain}`
Contract: `{ctx.contract_name or 'unknown'}`

## Generated Suite

- Foundry project: `generated_foundry`
- Generated ABI fuzz tests: {len(generated)}
- Skipped/unsupported ABI entries:
{skipped_blob}

## Detected Surfaces

{chr(10).join(f"- {s}" for s in surfaces)}

## Next Invariants To Build

{bullets}

## Elite Upgrade Path

- Convert each high-risk detector finding into one focused invariant.
- Add handler contracts that model attacker/honest-user roles and multi-step sequences.
- Run generated invariants with Foundry first, then export equivalent Echidna/Medusa campaigns.
"""
