"""Aderyn runner (Cyfrin's Rust static analyzer).

Aderyn has a detector set that overlaps only partially with Slither, so running it
adds genuine coverage. Its findings are normalized into the shared runner shape and
then promoted to candidates by `detectors/analyzer_findings.AnalyzerFindingsDetector`
(so they flow through the same sanity/refuter/scoring gates).

Install on the VPS: `cargo install aderyn` (or see github.com/Cyfrin/aderyn). The app
runs fine without it — Tool Health marks it missing and the scan records a skip.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..core.command_runner import run_command, which
from .base import RunnerResult

logger = logging.getLogger("bulkauditai.aderyn")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:48]


def _normalize(data: dict) -> list[dict]:
    """Aderyn report JSON -> shared finding shape.

    Defensive over the schema: any top-level ``<severity>_issues`` object with an
    ``issues`` list is consumed, so critical/high/medium/low are all handled and a
    schema tweak degrades gracefully instead of dropping everything.
    """
    findings: list[dict] = []
    if not isinstance(data, dict):
        return findings
    for key, val in data.items():
        if not (isinstance(key, str) and key.endswith("_issues") and isinstance(val, dict)):
            continue
        severity = key[: -len("_issues")].lower()  # critical | high | medium | low
        for issue in val.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            title = str(issue.get("title") or issue.get("detector_name") or "").strip()
            desc = str(issue.get("description") or "").strip()
            check = str(issue.get("detector_name") or "") or _slug(title) or "issue"
            location = ""
            instances = issue.get("instances") or []
            if instances and isinstance(instances[0], dict):
                inst = instances[0]
                location = f"{inst.get('contract_path', '')}:{inst.get('line_no', '')}"
            body = desc
            if title and title.lower() not in desc.lower():
                body = f"{title}. {desc}".strip()
            findings.append({
                "check": check,
                "impact": severity,
                "confidence": "",
                "description": body[:2000],
                "location": location,
                "function": "",
            })
    return findings


def run_aderyn(source_dir: Path, out_dir: Path, *, timeout: int = 240) -> RunnerResult:
    if which("aderyn") is None:
        return RunnerResult.skipped("aderyn", "aderyn not installed (cargo install aderyn)")

    out_dir.mkdir(parents=True, exist_ok=True)
    json_out = out_dir / "aderyn.json"

    cmd = run_command(
        ["aderyn", str(source_dir), "-o", str(json_out)],
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="aderyn",
    )
    result = RunnerResult.from_command("aderyn", cmd)

    if json_out.exists():
        try:
            data = json.loads(json_out.read_text(encoding="utf-8", errors="replace"))
            result.json_output_path = str(json_out)
            result.findings = _normalize(data)
            if result.status == "failed":
                result.status = "ok"  # aderyn may exit nonzero when issues are found
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("aderyn json parse failed: %s", exc)

    result.summary = (
        f"{len(result.findings)} issue(s)" if result.status == "ok" else f"aderyn {result.status}"
    )
    return result
