"""Finding detail + triage + per-finding export routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core import dedup, report_writer
from ..database import get_db
from ..models import AIReview, Finding, SuppressedFinding, Target
from ..schemas import AIReviewOut, FindingDetailOut, FindingStatusUpdate

router = APIRouter(prefix="/api", tags=["findings"])

_ALLOWED_STATUS = {"open", "false_positive", "needs_more_investigation", "confirmed"}


def _finding_fingerprint(f: Finding) -> str:
    ev = f.evidence_json or {}
    return ev.get("fingerprint") or dedup.fingerprint(
        f.detector, f.title, ev.get("affected_functions"), ev.get("file", "")
    )


class SuppressBody(BaseModel):
    global_: bool = False  # True => suppress this fingerprint on ALL contracts
    reason: str = "user-marked false-positive"


def _detail(db: Session, f: Finding) -> FindingDetailOut:
    detail = FindingDetailOut.model_validate(f)
    target = db.get(Target, f.target_id)
    detail.target_address = target.address if target else ""
    if f.ai_review_id:
        ai = db.get(AIReview, f.ai_review_id)
        if ai:
            detail.ai_review = AIReviewOut.model_validate(ai)
    return detail


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> FindingDetailOut:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    return _detail(db, f)


@router.post("/findings/{finding_id}/status", response_model=FindingDetailOut)
def set_status(
    finding_id: int, body: FindingStatusUpdate, db: Session = Depends(get_db)
) -> FindingDetailOut:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    if body.status not in _ALLOWED_STATUS:
        raise HTTPException(status_code=400, detail=f"status must be one of {_ALLOWED_STATUS}")
    f.status = body.status
    # FP-learning: marking a finding false-positive suppresses its fingerprint on
    # this contract for future scans (use /suppress for global).
    if body.status == "false_positive":
        target = db.get(Target, f.target_id)
        dedup.suppress(_finding_fingerprint(f),
                       address=(target.address if target else None),
                       detector=f.detector, title=f.title,
                       reason="marked false-positive via status")
    db.commit()
    db.refresh(f)
    return _detail(db, f)


@router.post("/findings/{finding_id}/suppress")
def suppress_finding(finding_id: int, body: SuppressBody, db: Session = Depends(get_db)) -> dict:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    target = db.get(Target, f.target_id)
    fp = _finding_fingerprint(f)
    address = None if body.global_ else (target.address if target else None)
    dedup.suppress(fp, address=address, detector=f.detector, title=f.title, reason=body.reason)
    f.status = "false_positive"
    db.commit()
    return {"suppressed": fp, "scope": "global" if body.global_ else "address",
            "address": address}


@router.get("/suppressions")
def list_suppressions(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(
        select(SuppressedFinding).order_by(SuppressedFinding.created_at.desc())
    ).all()
    return [{"id": r.id, "fingerprint": r.fingerprint, "address": r.address,
             "detector": r.detector, "title": r.title, "reason": r.reason,
             "created_at": r.created_at} for r in rows]


@router.delete("/suppressions/{sup_id}")
def delete_suppression(sup_id: int, db: Session = Depends(get_db)) -> dict:
    r = db.get(SuppressedFinding, sup_id)
    if not r:
        raise HTTPException(status_code=404, detail="suppression not found")
    db.delete(r)
    db.commit()
    return {"deleted": sup_id}


@router.get("/findings/{finding_id}/export")
def export_finding(
    finding_id: int,
    format: str = Query("md", pattern="^(md|markdown)$"),
    db: Session = Depends(get_db),
) -> Response:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    target = db.get(Target, f.target_id)
    ai = db.get(AIReview, f.ai_review_id) if f.ai_review_id else None
    md = report_writer.render_finding_markdown(f, target, ai)
    return Response(
        content=md.encode("utf-8"),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="finding_{finding_id}.md"'},
    )
