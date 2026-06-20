"""Scan + dashboard API routes."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core import exporter
from ..core.scanner import manager
from ..database import get_db
from ..detectors.registry import PROFILE_NAMES
from ..models import Finding, Scan, ScanStatus, Target
from ..schemas import (
    CreateScanRequest,
    DashboardStats,
    FindingOut,
    ScanDetailOut,
    ScanOut,
    TargetOut,
)

router = APIRouter(prefix="/api", tags=["scans"])

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")


def _normalize_targets(req: CreateScanRequest) -> list[tuple[str, str]]:
    """Return a deduped list of (checksum_address, label)."""
    seen: dict[str, str] = {}

    def add(addr: str, label: str = "") -> None:
        m = _ADDR_RE.fullmatch(addr.strip())
        if not m:
            return
        try:
            from eth_utils import to_checksum_address

            cs = to_checksum_address(addr.strip())
        except Exception:
            cs = addr.strip()
        if cs not in seen:
            seen[cs] = label.strip()

    for t in req.targets:
        add(t.address, t.label)

    for line in (req.addresses_blob or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # support "address,label" or "address label"
        parts = re.split(r"[,\t ]+", line, maxsplit=1)
        addr = parts[0]
        label = parts[1] if len(parts) > 1 else ""
        add(addr, label)

    return list(seen.items())


# Human labels for the scan profiles; anything not listed falls back to a
# title-cased version of the registry key, so the UI auto-shows new profiles.
_PROFILE_LABELS = {
    "quick": "Quick",
    "standard": "Standard",
    "deep": "Deep",
    "ultra-deep": "Ultra-deep (2026 exploit classes)",
    "defi-deep": "DeFi-deep",
    "oracle-focused": "Oracle-focused",
    "governance-focused": "Governance-focused",
    "zk-focused": "ZK-focused",
    "privacy-pool-focused": "Privacy-pool-focused",
    "bridge-focused": "Bridge-focused",
}


@router.get("/scan-profiles")
def scan_profiles() -> dict:
    """Authoritative scan-profile list (the registry is the single source of
    truth, so the UI dropdown can never drift from the backend)."""
    def _label(p: str) -> str:
        return _PROFILE_LABELS.get(p, p.replace("-", " ").title())

    return {"profiles": [{"value": p, "label": _label(p)} for p in PROFILE_NAMES]}


@router.get("/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db)) -> DashboardStats:
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
    running = sum(1 for s in scans if s.status == ScanStatus.RUNNING)
    completed = sum(1 for s in scans if s.status == ScanStatus.COMPLETED)
    return DashboardStats(
        total_scans=len(scans),
        running_scans=running,
        completed_scans=completed,
        critical_candidates=sum(s.critical_count for s in scans),
        needs_investigation=sum(s.needs_investigation_count for s in scans),
        low_info=sum(s.low_info_count for s in scans),
        false_positives=sum(s.false_positive_count for s in scans),
        recent_scans=[ScanOut.model_validate(s) for s in scans[:10]],
    )


@router.get("/scans", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)) -> list[ScanOut]:
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
    return [ScanOut.model_validate(s) for s in scans]


@router.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(req: CreateScanRequest, db: Session = Depends(get_db)) -> ScanOut:
    targets = _normalize_targets(req)
    if not targets:
        raise HTTPException(status_code=400, detail="no valid 0x addresses provided")

    scan = Scan(
        name=req.name or f"scan {len(targets)} targets",
        chain=req.chain,
        scan_profile=req.scan_profile,
        toggles=req.toggles.model_dump(exclude_none=True),
        total_targets=len(targets),
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    for addr, label in targets:
        db.add(Target(scan_id=scan.id, address=addr, chain=req.chain, label=label))
    db.commit()

    # Kick off the async pipeline on the running event loop.
    manager.start_scan(scan.id)
    db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanDetailOut:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    targets = db.scalars(
        select(Target).where(Target.scan_id == scan_id).order_by(Target.id)
    ).all()
    detail = ScanDetailOut.model_validate(scan)
    detail.targets = [TargetOut.model_validate(t) for t in targets]
    return detail


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanOut:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    manager.cancel_scan(scan_id)
    if scan.status in (ScanStatus.QUEUED,):
        scan.status = ScanStatus.CANCELLED
        db.commit()
    return ScanOut.model_validate(scan)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(scan_id: int, db: Session = Depends(get_db)) -> list[FindingOut]:
    target_ids = [
        t.id for t in db.scalars(select(Target).where(Target.scan_id == scan_id))
    ]
    if not target_ids:
        return []
    findings = db.scalars(
        select(Finding)
        .where(Finding.target_id.in_(target_ids))
        .order_by(Finding.impact_score.desc(), Finding.confidence_score.desc())
    ).all()
    return [FindingOut.model_validate(f) for f in findings]


@router.get("/scans/{scan_id}/export")
def export_scan(
    scan_id: int,
    format: str = Query("json", pattern="^(json|csv|md|markdown|zip)$"),
    db: Session = Depends(get_db),
) -> Response:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    fn, media_type, ext = exporter.EXPORTERS[format]
    data = fn(db, scan)
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="scan_{scan_id}.{ext}"'
        },
    )
