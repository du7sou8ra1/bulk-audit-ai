"""Mythril runner.

Analyzes the primary contract source file, then falls back to runtime bytecode if
source compilation fails. Mythril can return exit code 0 with JSON
``success:false`` when solc resolution fails, so the JSON success flag is treated
as authoritative.
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
    exec_timeout = max(30, timeout - 30)

    if main_source and main_source.exists():
        source_res, source_json = _run_source(
            exe,
            main_source,
            out_dir,
            solc_version=solc_version,
            exec_timeout=exec_timeout,
            timeout=timeout,
        )
        if _parsed_success(source_json):
            return _finish(source_res, source_json, main_source.name)
        if not source_res.timed_out and bytecode:
            bytecode_res, bytecode_json = _run_bytecode(
                exe,
                bytecode,
                out_dir,
                exec_timeout=exec_timeout,
                timeout=timeout,
            )
            if _parsed_success(bytecode_json):
                finished = _finish(bytecode_res, bytecode_json, "runtime bytecode")
                finished.summary = "source compile failed; bytecode fallback: " + finished.summary
                return finished
            fallback = _finish(bytecode_res, bytecode_json, "runtime bytecode")
            fallback.summary = "source compile failed; bytecode fallback: " + fallback.summary
            return fallback
        return _finish(source_res, source_json, main_source.name)

    if bytecode:
        bytecode_res, bytecode_json = _run_bytecode(
            exe,
            bytecode,
            out_dir,
            exec_timeout=exec_timeout,
            timeout=timeout,
        )
        return _finish(bytecode_res, bytecode_json, "runtime bytecode")

    return RunnerResult.skipped("mythril", "no source file or bytecode to analyze")


def _run_source(
    exe: str,
    main_source: Path,
    out_dir: Path,
    *,
    solc_version: str | None,
    exec_timeout: int,
    timeout: int,
) -> tuple[RunnerResult, dict | None]:
    args = [
        exe,
        "analyze",
        "-o",
        "json",
        "--execution-timeout",
        str(exec_timeout),
        str(main_source),
    ]
    if solc_version:
        args += ["--solv", solc_version]
    cmd = run_command(args, timeout=timeout, output_dir=out_dir, output_prefix="mythril_source")
    result = RunnerResult.from_command("mythril", cmd)
    parsed = _parse_stdout(cmd.stdout, out_dir / "mythril_source.json", result)
    return result, parsed


def _run_bytecode(
    exe: str,
    bytecode: str,
    out_dir: Path,
    *,
    exec_timeout: int,
    timeout: int,
) -> tuple[RunnerResult, dict | None]:
    bc_file = out_dir / "runtime.hex"
    clean_bytecode = (bytecode or "").strip()
    if clean_bytecode.startswith("0x"):
        clean_bytecode = clean_bytecode[2:]
    bc_file.write_text(clean_bytecode, encoding="utf-8")
    args = [
        exe,
        "analyze",
        "-o",
        "json",
        "--execution-timeout",
        str(exec_timeout),
        "--codefile",
        str(bc_file),
        "--bin-runtime",
    ]
    cmd = run_command(args, timeout=timeout, output_dir=out_dir, output_prefix="mythril_bytecode")
    result = RunnerResult.from_command("mythril", cmd)
    parsed = _parse_stdout(cmd.stdout, out_dir / "mythril_bytecode.json", result)
    return result, parsed


def _parse_stdout(stdout: str, json_out: Path, result: RunnerResult) -> dict | None:
    parsed: dict | None = None
    if stdout.strip():
        try:
            parsed = json.loads(stdout)
            json_out.write_text(stdout, encoding="utf-8")
            result.json_output_path = str(json_out)
        except json.JSONDecodeError:
            logger.debug("mythril stdout was not valid JSON")
    return parsed


def _finish(result: RunnerResult, parsed: dict | None, target_desc: str) -> RunnerResult:
    if parsed is not None:
        result.findings = _normalize(parsed)
        if parsed.get("success") is False:
            result.status = "failed"
            result.summary = f"mythril failed on {target_desc}: {_error_text(parsed)}"
            return result
        if parsed.get("success") is True:
            result.status = "ok"

    if result.status == "ok":
        result.summary = _summary(parsed, target_desc)
    else:
        result.summary = f"mythril {result.status} on {target_desc}"
    return result


def _summary(parsed: dict | None, target_desc: str) -> str:
    findings = _normalize(parsed or {})
    high = [f for f in findings if f.get("high_value")]
    return f"{len(findings)} issues on {target_desc} ({len(high)} high-value)"


def _parsed_success(parsed: dict | None) -> bool:
    return bool(parsed is not None and parsed.get("success") is True)


def _error_text(parsed: dict) -> str:
    error = str(parsed.get("error") or parsed.get("message") or "analysis did not succeed")
    return error.replace("\n", " ")[:300]
