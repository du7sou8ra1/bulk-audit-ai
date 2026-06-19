"""Slither runner.

Runs `slither <source_dir> --json <out>` and normalizes high/medium detector
results into evidence. If whole-directory compilation fails, falls back to
analyzing individual .sol files so a tricky import layout never wastes the run.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..core.command_runner import run_command, which
from .base import RunnerResult

logger = logging.getLogger("bulkauditai.slither")

# Detectors we care most about (others are still recorded, just not highlighted).
HIGH_VALUE_CHECKS = {
    "unprotected-upgrade",
    "controlled-delegatecall",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "reentrancy-eth",
    "reentrancy-no-eth",
    "unchecked-transfer",
    "unchecked-lowlevel",
    "tx-origin",
    "suicidal",
    "uninitialized-state",
    "uninitialized-storage",
    "shadowing-state",
    "incorrect-equality",
    "delegatecall-loop",
}


def _maybe_select_solc(version: str | None) -> None:
    """Best-effort: install + select a solc version via solc-select."""
    if not version or which("solc-select") is None:
        return
    run_command(["solc-select", "install", version], timeout=120)
    run_command(["solc-select", "use", version], timeout=30)


def _normalize(results_json: dict) -> list[dict]:
    findings: list[dict] = []
    detectors = (results_json.get("results") or {}).get("detectors") or []
    for d in detectors:
        impact = (d.get("impact") or "").lower()
        check = d.get("check") or ""
        # Keep High/Medium plus any high-value check regardless of impact.
        if impact not in ("high", "medium") and check not in HIGH_VALUE_CHECKS:
            continue
        elements = d.get("elements") or []
        location = ""
        if elements:
            sm = (elements[0].get("source_mapping") or {})
            location = f"{sm.get('filename_short', '')}:{sm.get('lines', '')}"
        findings.append(
            {
                "check": check,
                "impact": impact,
                "confidence": (d.get("confidence") or "").lower(),
                "description": (d.get("description") or "").strip()[:2000],
                "location": location,
                "high_value": check in HIGH_VALUE_CHECKS,
            }
        )
    return findings


def run_slither(
    source_dir: Path,
    out_dir: Path,
    *,
    solc_version: str | None = None,
    timeout: int = 180,
) -> RunnerResult:
    if which("slither") is None:
        return RunnerResult.skipped("slither", "slither not installed (pip install slither-analyzer)")

    out_dir.mkdir(parents=True, exist_ok=True)
    json_out = out_dir / "slither.json"
    _maybe_select_solc(solc_version)

    cmd = run_command(
        ["slither", str(source_dir), "--json", str(json_out)],
        timeout=timeout,
        cwd=source_dir,
        output_dir=out_dir,
        output_prefix="slither",
    )
    result = RunnerResult.from_command("slither", cmd)

    parsed = _parse_json(json_out)
    if parsed is None and not json_out.exists():
        # Fallback: analyze .sol files individually.
        sol_files = sorted(source_dir.rglob("*.sol"))
        for i, sol in enumerate(sol_files[:25]):  # cap to keep runs bounded
            fjson = out_dir / f"slither_file_{i}.json"
            run_command(
                ["slither", str(sol), "--json", str(fjson)],
                timeout=max(30, timeout // 4),
                output_dir=out_dir,
                output_prefix=f"slither_file_{i}",
            )
            p = _parse_json(fjson)
            if p:
                parsed = parsed or {"results": {"detectors": []}}
                parsed["results"]["detectors"].extend(
                    (p.get("results") or {}).get("detectors") or []
                )

    if parsed is not None:
        result.json_output_path = str(json_out)
        result.findings = _normalize(parsed)
        # Slither returns nonzero when it finds issues — that's still a success.
        if result.status == "failed" and result.findings:
            result.status = "ok"

    high = [f for f in result.findings if f.get("high_value") or f.get("impact") == "high"]
    result.summary = (
        f"{len(result.findings)} detector hits ({len(high)} high-value/high-impact)"
        if result.status == "ok"
        else f"slither {result.status}"
    )
    return result


def _parse_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
