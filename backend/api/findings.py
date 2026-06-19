"""Finding detail + triage + per-finding export routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..core import report_writer
from ..database import get_db
from ..models import AIReview, Finding, Target
from ..schemas import AIReviewOut, FindingDetailOut, FindingStatusUpdate

router = APIRouter(prefix="/api", tags=["findings"])

_ALLOWED_STATUS = {"open", "false_positive", "needs_more_investigation", "confirmed"}


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
    db.commit()
    db.refresh(f)
    return _detail(db, f)


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
