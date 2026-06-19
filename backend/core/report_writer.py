"""Markdown report drafting.

Drafts are generated ONLY for CONFIRMED_CRITICAL and LIKELY_CRITICAL_NEEDS_POC
findings. If no PoC/fork confirmation exists, the report is explicitly marked
"Not submit-ready".
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import ROOT_DIR
from ..models import AIReview, Classification, Finding, Target

TEMPLATE_PATH = ROOT_DIR / "backend" / "templates" / "report_template.md"

REPORTABLE = {Classification.CONFIRMED_CRITICAL, Classification.LIKELY_CRITICAL_NEEDS_POC}

NOT_SUBMIT_READY = (
    "> ⚠️ **Not submit-ready. Needs PoC/fork confirmation.** "
    "This draft is a triage candidate, not a verified report."
)
SUBMIT_READY = "> This finding has reproducible evidence. Re-verify before submitting."


def is_reportable(finding: Finding) -> bool:
    return finding.classification in REPORTABLE


def _fmt_block(value) -> str:
    if value in (None, "", [], {}):
        return "_n/a_"
    if isinstance(value, (dict, list)):
        return "```json\n" + json.dumps(value, indent=2, default=str)[:4000] + "\n```"
    return str(value)


def render_finding_markdown(
    finding: Finding, target: Target, ai_review: AIReview | None
) -> str:
    tmpl = (
        TEMPLATE_PATH.read_text(encoding="utf-8")
        if TEMPLATE_PATH.exists()
        else "# {{TITLE}}\n{{SUMMARY}}\n{{EVIDENCE}}\n{{SUBMIT_READY_NOTE}}"
    )
    ev = finding.evidence_json or {}
    onchain = {
        k: ev.get(k)
        for k in (
            "proxy_admin",
            "proxy_admin_owner",
            "owner",
            "implementation",
            "open_roles",
            "min_delay_seconds",
        )
        if k in ev
    }
    poc_exists = bool(ev.get("open_roles") or ev.get("unguarded") or ev.get("poc_passed"))
    next_tests = finding.next_tests_json or []
    rationale = ai_review.rationale if ai_review else ""

    mapping = {
        "{{TITLE}}": finding.title,
        "{{SEVERITY}}": finding.severity_candidate,
        "{{CLASSIFICATION}}": finding.classification,
        "{{IMPACT}}": f"{finding.impact_score:.0f}",
        "{{CONFIDENCE}}": f"{finding.confidence_score:.0f}",
        "{{ADDRESS}}": target.address,
        "{{CHAIN}}": target.chain,
        "{{CONTRACT_NAME}}": target.contract_name or "unknown",
        "{{DETECTOR}}": finding.detector,
        "{{SUMMARY}}": finding.description,
        "{{IMPACT_TEXT}}": rationale or finding.description,
        "{{ROOT_CAUSE}}": _fmt_block(ev.get("snippet") or ev.get("description") or "_see evidence_"),
        "{{AFFECTED_FUNCTIONS}}": ", ".join(ev.get("affected_functions", []))
        or ", ".join(finding.next_tests_json and [] or [])
        or _fmt_block(ev.get("function", "_n/a_")),
        "{{EVIDENCE}}": _fmt_block(ev),
        "{{ONCHAIN}}": _fmt_block(onchain),
        "{{POC}}": "Read-only fork probe can be generated (see tools/foundry/)."
        if not poc_exists
        else "On-chain/static evidence present; build a fork PoC to finalize.",
        "{{LIMITATIONS}}": "Triage-stage finding. No state-changing exploit was run. "
        "All checks were read-only (eth_call / static analysis).",
        "{{FIX}}": "_To be completed after confirmation._",
        "{{DISCLOSURE}}": "Defensive research / bug-bounty triage only. Do not exploit live contracts.",
        "{{SUBMIT_READY_NOTE}}": SUBMIT_READY if poc_exists else NOT_SUBMIT_READY,
    }
    out = tmpl
    for k, v in mapping.items():
        out = out.replace(k, str(v))
    return out


def write_report(
    finding: Finding, target: Target, ai_review: AIReview | None, out_dir: Path
) -> Path | None:
    if not is_reportable(finding):
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    md = render_finding_markdown(finding, target, ai_review)
    path = out_dir / f"finding_{finding.id}_{finding.detector}.md"
    path.write_text(md, encoding="utf-8")
    return path
