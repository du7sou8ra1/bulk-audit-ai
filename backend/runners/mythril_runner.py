"""Mythril runner.

Analyzes the primary contract source file (or bytecode) with a hard timeout.
Mythril is slow, so the runner targets the main contract only and respects the
configured execution timeout. Output is normalized into evidence.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..core.command_runner import run_command, which
from .base import RunnerResult

logger = logging.getLogger("bulkauditai.mythril")

HIGH_VALUE_TITLES = (
    "delegatecall",
    "selfdestruct",
    "suicide",
    "unchecked",
    "arbitrary",
    "ether",
    "reentran",
    "authorization",
    "write to an arbitrary storage",
)


def _myth_executable() -> str | None:
    for candidate in ("myth", "mythril"):
        if which(candidate):
            return candidate
    return None


def _normalize(data: dict) -> list[dict]:
    findings: list[dict] = []
    issues = data.get("issues") or []
    for issue in issues:
        title = issue.get("title", "") or issue.get("swc-id", "")
        findings.append(
            {
                "check": title,
                "impact": (issue.get("severity") or "").lower(),
                "confidence": "",
                "description": (issue.get("description") or "").strip()[:2000],
                "location": f"{issue.get('filename', '')}:{issue.get('lineno', '')}",
                "swc_id": issue.get("swc-id", ""),
                "high_value": any(k in title.lower() for k in HIGH_VALUE_TITLES),
            }
        )
    return findings


def run_mythril(
    main_source: Path | None,
    out_dir: Path,
    *,
    bytecode: str | None = None,
    solc_version: str | None = None,
    timeout: int = 300,
) -> RunnerResult:
    exe = _myth_executable()
    if exe is None:
        return RunnerResult.skipped("mythril", "mythril not installed (pip install mythril)")

    out_dir.mkdir(parents=True, exist_ok=True)
    # execution-timeout must be shorter than our process timeout.
    exec_timeout = max(30, timeout - 30)

    args = [exe, "analyze", "-o", "json", "--execution-timeout", str(exec_timeout)]
    target_desc = ""
    if main_source and main_source.exists():
        args.append(str(main_source))
        if solc_version:
            args += ["--solv", solc_version]
        target_desc = main_source.name
    elif bytecode:
        bc_file = out_dir / "runtime.hex"
        bc_file.write_text(bytecode, encoding="utf-8")
        args += ["--codefile", str(bc_file)]
        target_desc = "runtime bytecode"
    else:
        return RunnerResult.skipped("mythril", "no source file or bytecode to analyze")

    cmd = run_command(args, timeout=timeout, output_dir=out_dir, output_prefix="mythril")
    result = RunnerResult.from_command("mythril", cmd)

    # Mythril prints JSON to stdout.
    json_out = out_dir / "mythril.json"
    parsed: dict | None = None
    if cmd.stdout.strip():
        try:
            parsed = json.loads(cmd.stdout)
            json_out.write_text(cmd.stdout, encoding="utf-8")
            result.json_output_path = str(json_out)
        except json.JSONDecodeError:
            logger.debug("mythril stdout was not valid JSON")

    if parsed is not None:
        result.findings = _normalize(parsed)
        if result.status == "failed" and parsed.get("success"):
            result.status = "ok"

    high = [f for f in result.findings if f.get("high_value")]
    result.summary = (
        f"{len(result.findings)} issues on {target_desc} ({len(high)} high-value)"
        if result.status in ("ok",)
        else f"mythril {result.status} on {target_desc}"
    )
    return result
