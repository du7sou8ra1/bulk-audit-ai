"""Export a scan to JSON / CSV / Markdown / zipped evidence."""
from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import AIReview, Finding, Scan, Target
from . import report_writer


def _scan_dict(db: Session, scan: Scan) -> dict:
    targets = db.scalars(select(Target).where(Target.scan_id == scan.id)).all()
    out_targets = []
    for t in targets:
        findings = db.scalars(select(Finding).where(Finding.target_id == t.id)).all()
        f_list = []
        for f in findings:
            ai = db.get(AIReview, f.ai_review_id) if f.ai_review_id else None
            f_list.append(
                {
                    "id": f.id,
                    "detector": f.detector,
                    "title": f.title,
                    "severity_candidate": f.severity_candidate,
                    "impact_score": f.impact_score,
                    "confidence_score": f.confidence_score,
                    "classification": f.classification,
                    "status": f.status,
                    "description": f.description,
                    "evidence": f.evidence_json,
                    "next_tests": f.next_tests_json,
                    "ai_rationale": ai.rationale if ai else None,
                }
            )
        out_targets.append(
            {
                "address": t.address,
                "contract_name": t.contract_name,
                "is_proxy": t.is_proxy,
                "proxy_type": t.proxy_type,
                "implementation": t.implementation_address,
                "admin": t.proxy_admin,
                "owner": t.owner,
                "balance_eth": t.balance_eth,
                "source_verified": t.source_verified,
                "findings": f_list,
            }
        )
    return {
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "chain": scan.chain,
            "profile": scan.scan_profile,
            "status": scan.status,
            "total_targets": scan.total_targets,
            "critical_count": scan.critical_count,
            "needs_investigation_count": scan.needs_investigation_count,
            "low_info_count": scan.low_info_count,
            "false_positive_count": scan.false_positive_count,
        },
        "targets": out_targets,
    }


def export_json(db: Session, scan: Scan) -> bytes:
    return json.dumps(_scan_dict(db, scan), indent=2, default=str).encode("utf-8")


def export_csv(db: Session, scan: Scan) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["address", "detector", "title", "impact", "confidence", "classification", "status", "next_test"]
    )
    targets = db.scalars(select(Target).where(Target.scan_id == scan.id)).all()
    for t in targets:
        findings = db.scalars(select(Finding).where(Finding.target_id == t.id)).all()
        for f in findings:
            nxt = (f.next_tests_json or [""])[0] if f.next_tests_json else ""
            writer.writerow(
                [
                    t.address,
                    f.detector,
                    f.title,
                    f"{f.impact_score:.0f}",
                    f"{f.confidence_score:.0f}",
                    f.classification,
                    f.status,
                    nxt,
                ]
            )
    return buf.getvalue().encode("utf-8")


def export_markdown(db: Session, scan: Scan) -> bytes:
    lines = [
        f"# BulkAuditAI report — scan #{scan.id} ({scan.name or 'unnamed'})",
        "",
        f"- Chain: {scan.chain}  •  Profile: {scan.scan_profile}  •  Status: {scan.status}",
        f"- Targets: {scan.total_targets}  •  Critical candidates: {scan.critical_count}  "
        f"•  Needs investigation: {scan.needs_investigation_count}",
        "",
        "> Defensive bug-bounty triage. Candidates are NOT confirmed bugs.",
        "",
    ]
    targets = db.scalars(select(Target).where(Target.scan_id == scan.id)).all()
    any_report = False
    for t in targets:
        findings = db.scalars(select(Finding).where(Finding.target_id == t.id)).all()
        reportable = [f for f in findings if report_writer.is_reportable(f)]
        if not reportable:
            continue
        any_report = True
        lines.append(f"\n---\n## Target `{t.address}` ({t.contract_name or 'unknown'})\n")
        for f in reportable:
            ai = db.get(AIReview, f.ai_review_id) if f.ai_review_id else None
            lines.append(report_writer.render_finding_markdown(f, t, ai))
            lines.append("")
    if not any_report:
        lines.append("\n_No CONFIRMED_CRITICAL or LIKELY_CRITICAL_NEEDS_POC findings to report._")
    return "\n".join(lines).encode("utf-8")


def export_zip(db: Session, scan: Scan) -> bytes:
    """Zip the scan's evidence workspace plus a summary JSON."""
    buf = io.BytesIO()
    scan_dir = get_settings().output_path / str(scan.id)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("summary.json", json.dumps(_scan_dict(db, scan), indent=2, default=str))
        zf.writestr("report.md", export_markdown(db, scan).decode("utf-8"))
        zf.writestr("findings.csv", export_csv(db, scan).decode("utf-8"))
        if scan_dir.exists():
            for path in scan_dir.rglob("*"):
                if path.is_file():
                    try:
                        zf.write(path, arcname=str(Path("evidence") / path.relative_to(scan_dir)))
                    except OSError:
                        continue
    return buf.getvalue()


EXPORTERS = {
    "json": (export_json, "application/json", "json"),
    "csv": (export_csv, "text/csv", "csv"),
    "md": (export_markdown, "text/markdown", "md"),
    "markdown": (export_markdown, "text/markdown", "md"),
    "zip": (export_zip, "application/zip", "zip"),
}
