"""Settings (masked) + Tool Health routes."""
from __future__ import annotations

from fastapi import APIRouter

from ..config import masked_settings
from ..core.tool_health import check_tools

router = APIRouter(prefix="/api", tags=["settings"])


@router.get("/settings")
def get_settings_masked() -> dict:
    """Return UI-safe settings. Secrets are masked; nothing comes from the DB."""
    return masked_settings()


@router.get("/health/tools")
def tool_health() -> dict:
    return check_tools()
