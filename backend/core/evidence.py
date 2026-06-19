"""Workspace isolation + compact evidence packets for the AI reviewer.

Workspace layout (never overwrites old scans):

    outputs/scans/<scan_id>/<target_address>/
        source/
        tools/{slither,mythril,semgrep,foundry}/
        evidence/
        ai/
        reports/
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from ..config import get_settings
from ..detectors.base import FindingCandidate, TargetContext
from .scoring import ScoreResult


def create_target_workspace(scan_id: int, address: str) -> dict[str, Path]:
    base = get_settings().output_path / str(scan_id) / address.lower()
    paths = {
        "base": base,
        "source": base / "source",
        "tools": base / "tools",
        "slither": base / "tools" / "slither",
        "mythril": base / "tools" / "mythril",
        "semgrep": base / "tools" / "semgrep",
        "foundry": base / "tools" / "foundry",
        "evidence": base / "evidence",
        "ai": base / "ai",
        "reports": base / "reports",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths


def _trim(value, max_str: int = 1500, max_list: int = 12):
    """Recursively trim strings/lists so AI packets stay compact + deterministic."""
    if isinstance(value, str):
        return value if len(value) <= max_str else value[:max_str] + " …[truncated]"
    if isinstance(value, list):
        return [_trim(v, max_str, max_list) for v in value[:max_list]]
    if isinstance(value, dict):
        return {k: _trim(v, max_str, max_list) for k, v in value.items()}
    return value


def build_ai_packet(
    ctx: TargetContext,
    candidate: FindingCandidate,
    score: ScoreResult,
) -> dict:
    """Construct the compact structured evidence packet for DeepSeek."""
    proxy = ctx.proxy_info
    onchain_checks = {
        "rpc_available": ctx.onchain.available,
        "slot_reads": (proxy.evidence or {}).get("slot_reads", {}),
        "abi_calls": (proxy.evidence or {}).get("abi_calls", {}),
        "proxy_admin": proxy.admin,
        "proxy_admin_owner": proxy.admin_owner,
        "owner": proxy.owner,
        "implementation": proxy.implementation,
    }

    # Pull a couple of relevant source snippets.
    snippets = []
    if candidate.evidence.get("snippet"):
        snippets.append(
            {
                "file": candidate.evidence.get("file", ""),
                "code": candidate.evidence["snippet"],
            }
        )

    tool_summaries = {
        "slither": (ctx.tool_outputs.get("slither") or {}).get("findings", []),
        "mythril": (ctx.tool_outputs.get("mythril") or {}).get("findings", []),
        "semgrep": (ctx.tool_outputs.get("semgrep") or {}).get("findings", []),
    }

    packet = {
        "target": {
            "address": ctx.address,
            "chain": ctx.chain,
            "contract_name": ctx.contract_name,
            "is_proxy": proxy.is_proxy,
            "proxy_type": proxy.proxy_type,
            "implementation": proxy.implementation,
            "admin": proxy.admin,
            "admin_owner": proxy.admin_owner,
            "owner": proxy.owner,
        },
        "candidate": {
            "detector": candidate.detector,
            "title": candidate.title,
            "description": candidate.description,
            "affected_functions": candidate.affected_functions,
            "pre_ai_impact": score.impact_score,
            "pre_ai_confidence": score.confidence_score,
            "pre_ai_classification": score.classification,
            "score_notes": score.score_notes,
        },
        "evidence": candidate.evidence,
        "tool_summaries": tool_summaries,
        "onchain_checks": onchain_checks,
        "source_snippets": snippets,
        "next_tests_suggested": candidate.next_tests,
    }
    return _trim(packet)


def write_finding_evidence(
    workspace: dict[str, Path], slug: str, candidate: FindingCandidate, packet: dict
) -> Path:
    """Persist deterministic JSON evidence for a finding."""
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", slug)[:80]
    path = workspace["evidence"] / f"{safe}.json"
    blob = {
        "candidate": asdict(candidate),
        "ai_packet": packet,
    }
    path.write_text(json.dumps(blob, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path
