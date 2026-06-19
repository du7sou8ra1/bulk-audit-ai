"""Foundry runner — READ-ONLY fork simulations only.

SAFETY: this runner never broadcasts. It only ever generates and (optionally)
runs `forge test --fork-url <rpc>` style tests, which execute against a LOCAL
fork. There is no `forge script --broadcast`, no private keys, no `cast send`.
For the MVP, the default is to GENERATE tests for strong candidates, not run
them, unless ENABLE_FOUNDRY is set.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..config import ROOT_DIR
from ..core.command_runner import run_command, which
from .base import RunnerResult

logger = logging.getLogger("bulkauditai.foundry")

TEMPLATE_PATH = ROOT_DIR / "backend" / "templates" / "foundry_tests" / "ForkProbe.t.sol.tmpl"

# A defensive denylist: if any of these ever appear in a generated/known test or
# the foundry config we refuse to run it. Keeps the "no broadcast / no send /
# no key / no ffi" guarantee enforceable as a backstop.
FORBIDDEN_TOKENS = (
    "--broadcast",
    "vm.broadcast",
    "vm.startBroadcast",
    "startBroadcast(",
    "cast send",
    "privateKey",
    "--private-key",
    "vm.sign(",
    "mnemonic",
    "vm.ffi(",
    "ffi = true",
    "ffi=true",
)


def generate_fork_test(
    target_address: str,
    out_dir: Path,
    *,
    contract_name: str = "Target",
    notes: str = "",
) -> Path:
    """Render a read-only fork probe test for a candidate. Does not run it."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if TEMPLATE_PATH.exists():
        tmpl = TEMPLATE_PATH.read_text(encoding="utf-8")
    else:
        tmpl = _DEFAULT_TEMPLATE
    rendered = (
        tmpl.replace("{{TARGET}}", target_address)
        .replace("{{CONTRACT}}", contract_name or "Target")
        .replace("{{NOTES}}", notes or "auto-generated read-only fork probe")
    )
    test_path = out_dir / "ForkProbe.t.sol"
    test_path.write_text(rendered, encoding="utf-8")
    return test_path


def _parse_forge_json(stdout: str) -> tuple[int, int]:
    """Parse `forge test --json` output -> (tests_run, tests_passed).

    Handles the suite-keyed shape: {"<artifact>": {"test_results": {"<sig>":
    {"status": "Success"|"Failure", "success": bool}}}}. Tolerant of forge
    version differences (uses either `status` or `success`).
    """
    import json

    text = (stdout or "").strip()
    if not text:
        return 0, 0
    # forge may print a non-JSON line before the object; grab the first {...}.
    if not text.startswith("{"):
        brace = text.find("{")
        if brace == -1:
            return 0, 0
        text = text[brace:]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return 0, 0

    run = passed = 0
    if isinstance(data, dict):
        for suite in data.values():
            if not isinstance(suite, dict):
                continue
            results = suite.get("test_results") or {}
            if not isinstance(results, dict):
                continue
            for entry in results.values():
                if not isinstance(entry, dict):
                    continue
                run += 1
                ok = entry.get("success")
                if ok is None:
                    ok = str(entry.get("status", "")).lower() == "success"
                if ok:
                    passed += 1
    return run, passed


def run_forge_tests(
    project_dir: Path,
    out_dir: Path,
    *,
    rpc_url: str,
    timeout: int = 300,
    match_path: str | None = None,
) -> RunnerResult:
    if which("forge") is None:
        return RunnerResult.skipped("foundry", "forge not installed (run foundryup)")
    if not rpc_url:
        return RunnerResult.skipped("foundry", "no RPC_URL configured for fork test")

    # Enforce read-only: scan generated tests AND the foundry config for
    # forbidden tokens (broadcast / send / private key / ffi) before running.
    scan_files = list(project_dir.rglob("*.sol"))
    toml = project_dir / "foundry.toml"
    if toml.exists():
        scan_files.append(toml)
    for t in scan_files:
        try:
            content = t.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(tok in content for tok in FORBIDDEN_TOKENS):
            return RunnerResult.skipped(
                "foundry", f"refusing to run: forbidden broadcast/send/ffi token in {t.name}"
            )

    out_dir.mkdir(parents=True, exist_ok=True)
    args = ["forge", "test", "--json", "--fork-url", rpc_url]
    if match_path:
        args += ["--match-path", match_path]
    cmd = run_command(
        args,
        timeout=timeout,
        cwd=project_dir,
        output_dir=out_dir,
        output_prefix="forge_test",
    )
    result = RunnerResult.from_command("foundry", cmd)

    tests_run, tests_passed = _parse_forge_json(cmd.stdout)
    result.meta = {"tests_run": tests_run, "tests_passed": tests_passed}

    # A PoC "pass" REQUIRES that a test actually executed and succeeded.
    # `forge test` exits 0 even when zero tests are discovered — guard against
    # that footgun so we never report a bogus confirmation.
    if result.status == "timeout":
        result.summary = "forge test timed out"
    elif result.status == "skipped":
        result.summary = "forge not available"
    elif tests_run == 0:
        result.status = "failed"
        result.summary = "no tests executed (inconclusive)"
    elif tests_passed == tests_run:
        result.status = "ok"
        result.summary = f"{tests_passed}/{tests_run} fork tests passed"
    else:
        result.status = "failed"
        result.summary = f"{tests_passed}/{tests_run} fork tests passed (some failed)"
    return result


_DEFAULT_TEMPLATE = """// SPDX-License-Identifier: MIT
// AUTO-GENERATED READ-ONLY FORK PROBE — DO NOT BROADCAST.
// {{NOTES}}
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

interface ITarget {
    function owner() external view returns (address);
    function admin() external view returns (address);
    function implementation() external view returns (address);
}

contract ForkProbe is Test {
    address constant TARGET = {{TARGET}};

    function test_readonly_probe() public {
        // Read-only assertions only. Extend with eth_call-style staticcalls.
        // NEVER use vm.broadcast / private keys here.
        uint256 size;
        address t = TARGET;
        assembly { size := extcodesize(t) }
        emit log_named_uint("codesize", size);
        assertTrue(size > 0, "target has no code on fork");
    }
}
"""
