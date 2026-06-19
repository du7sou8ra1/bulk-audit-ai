"""Semgrep runner using the bundled local Solidity ruleset."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import ROOT_DIR
from ..core.command_runner import run_command, which
from .base import RunnerResult

logger = logging.getLogger("bulkauditai.semgrep")

RULES_DIR = ROOT_DIR / "backend" / "semgrep_rules"


def _normalize(data: dict) -> list[dict]:
    findings: list[dict] = []
    for r in data.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        findings.append(
            {
                "check": r.get("check_id", ""),
                "impact": (extra.get("severity") or "").lower(),
                "confidence": (extra.get("metadata", {}) or {}).get("confidence", ""),
                "description": (extra.get("message") or "").strip()[:2000],
                "location": f"{r.get('path', '')}:{(r.get('start', {}) or {}).get('line', '')}",
            }
        )
    return findings


def run_semgrep(source_dir: Path, out_dir: Path, *, timeout: int = 120) -> RunnerResult:
    if which("semgrep") is None:
        return RunnerResult.skipped("semgrep", "semgrep not installed (pip install semgrep)")

    out_dir.mkdir(parents=True, exist_ok=True)
    json_out = out_dir / "semgrep.json"
    config = str(RULES_DIR) if RULES_DIR.exists() else "auto"

    cmd = run_command(
        [
            "semgrep",
            "--config",
            config,
            "--json",
            "--output",
            str(json_out),
            "--quiet",
            "--no-git-ignore",
            str(source_dir),
        ],
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="semgrep",
    )
    result = RunnerResult.from_command("semgrep", cmd)

    if json_out.exists():
        try:
            data = json.loads(json_out.read_text(encoding="utf-8", errors="replace"))
            result.json_output_path = str(json_out)
            result.findings = _normalize(data)
            if result.status == "failed":
                result.status = "ok"  # semgrep returns nonzero when matches found
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("semgrep json parse failed: %s", exc)

    result.summary = (
        f"{len(result.findings)} rule matches"
        if result.status == "ok"
        else f"semgrep {result.status}"
    )
    return result
