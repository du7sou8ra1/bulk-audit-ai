"""Target (contract) detail routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Finding, Target, ToolRun
from ..schemas import FindingOut, TargetDetailOut, ToolRunOut

router = APIRouter(prefix="/api", tags=["targets"])


@router.get("/targets/{target_id}", response_model=TargetDetailOut)
def get_target(target_id: int, db: Session = Depends(get_db)) -> TargetDetailOut:
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(status_code=404, detail="target not found")
    tool_runs = db.scalars(
        select(ToolRun).where(ToolRun.target_id == target_id).order_by(ToolRun.id)
    ).all()
    findings = db.scalars(
        select(Finding)
        .where(Finding.target_id == target_id)
        .order_by(Finding.impact_score.desc())
    ).all()
    detail = TargetDetailOut.model_validate(t)
    detail.tool_runs = [ToolRunOut.model_validate(tr) for tr in tool_runs]
    detail.findings = [FindingOut.model_validate(f) for f in findings]
    return detail
