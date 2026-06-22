"""Watchlist + monitor-control API ("before-drain" layer)."""
from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..core import alerting
from ..core.monitor import check_deployer_watch, check_watch_target, monitor
from ..database import get_db
from ..models import DeployerWatch, WatchEvent, WatchTarget

router = APIRouter(prefix="/api", tags=["watch"])

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")


class AddWatchRequest(BaseModel):
    addresses_blob: str = ""
    addresses: list[str] = []
    chain: str = "ethereum"
    scan_profile: str = "deep"
    github_url: str | None = None
    interval_seconds: int | None = None


def _norm(addr: str) -> str | None:
    if not _ADDR_RE.fullmatch(addr.strip()):
        return None
    try:
        from eth_utils import to_checksum_address
        return to_checksum_address(addr.strip())
    except Exception:
        return addr.strip()


@router.post("/watch", status_code=201)
def add_watch(req: AddWatchRequest, db: Session = Depends(get_db)) -> dict:
    raw = list(req.addresses) + (req.addresses_blob or "").splitlines()
    addrs = []
    for line in raw:
        a = _norm(line.split(",")[0].split()[0]) if line.strip() else None
        if a and a not in addrs:
            addrs.append(a)
    if not addrs:
        raise HTTPException(400, "no valid 0x addresses")
    existing = {w.address.lower() for w in db.scalars(select(WatchTarget))}
    added = []
    for a in addrs:
        if a.lower() in existing:
            continue
        w = WatchTarget(address=a, chain=req.chain, scan_profile=req.scan_profile,
                        github_url=req.github_url, interval_seconds=req.interval_seconds)
        db.add(w)
        added.append(a)
    db.commit()
    return {"added": added, "skipped_existing": [a for a in addrs if a not in added]}


@router.get("/watch")
def list_watch(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(WatchTarget).order_by(WatchTarget.created_at.desc())).all()
    return [_watch_dict(w) for w in rows]


@router.get("/watch/{watch_id}")
def get_watch(watch_id: int, db: Session = Depends(get_db)) -> dict:
    w = db.get(WatchTarget, watch_id)
    if not w:
        raise HTTPException(404, "watch target not found")
    events = db.scalars(
        select(WatchEvent).where(WatchEvent.watch_target_id == watch_id)
        .order_by(WatchEvent.created_at.desc())
    ).all()
    d = _watch_dict(w)
    d["events"] = [{"kind": e.kind, "detail": e.detail, "scan_id": e.scan_id,
                    "created_at": e.created_at} for e in events]
    return d


@router.delete("/watch/{watch_id}")
def delete_watch(watch_id: int, db: Session = Depends(get_db)) -> dict:
    w = db.get(WatchTarget, watch_id)
    if not w:
        raise HTTPException(404, "watch target not found")
    db.delete(w)
    db.commit()
    return {"deleted": watch_id}


@router.post("/watch/{watch_id}/check")
async def check_now(watch_id: int) -> dict:
    """Run a change-check immediately; start a rescan if a change is detected."""
    res = await asyncio.to_thread(check_watch_target, watch_id)
    if res.get("scan_id"):
        from ..core.scanner import manager
        manager.start_scan(res["scan_id"])
    return res


@router.post("/monitor/start")
def monitor_start() -> dict:
    monitor.start()
    return monitor_status()


@router.post("/monitor/stop")
def monitor_stop() -> dict:
    monitor.stop()
    return monitor_status()


@router.get("/monitor/status")
def monitor_status() -> dict:
    s = get_settings()
    return {"running": monitor.running, "interval_seconds": s.monitor_interval_seconds,
            "alerts_configured": alerting.alerts_enabled(),
            "enable_monitor_default": s.enable_monitor}


class AddDeployerRequest(BaseModel):
    addresses_blob: str = ""
    addresses: list[str] = []
    chain: str = "ethereum"
    scan_profile: str = "deep"
    interval_seconds: int | None = None


@router.post("/deployers", status_code=201)
def add_deployer(req: AddDeployerRequest, db: Session = Depends(get_db)) -> dict:
    raw = list(req.addresses) + (req.addresses_blob or "").splitlines()
    addrs = []
    for line in raw:
        a = _norm(line.split(",")[0].split()[0]) if line.strip() else None
        if a and a not in addrs:
            addrs.append(a)
    if not addrs:
        raise HTTPException(400, "no valid 0x deployer addresses")
    existing = {d.deployer_address.lower() for d in db.scalars(select(DeployerWatch))}
    added = []
    for a in addrs:
        if a.lower() in existing:
            continue
        db.add(DeployerWatch(deployer_address=a, chain=req.chain,
                             scan_profile=req.scan_profile, interval_seconds=req.interval_seconds))
        added.append(a)
    db.commit()
    return {"added": added, "skipped_existing": [a for a in addrs if a not in added]}


@router.get("/deployers")
def list_deployers(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(DeployerWatch).order_by(DeployerWatch.created_at.desc())).all()
    return [_deployer_dict(d) for d in rows]


@router.delete("/deployers/{dw_id}")
def delete_deployer(dw_id: int, db: Session = Depends(get_db)) -> dict:
    d = db.get(DeployerWatch, dw_id)
    if not d:
        raise HTTPException(404, "deployer watch not found")
    db.delete(d)
    db.commit()
    return {"deleted": dw_id}


@router.post("/deployers/{dw_id}/check")
async def check_deployer_now(dw_id: int) -> dict:
    """Scan a watched deployer for new contracts now; onboard + rescan each."""
    res = await asyncio.to_thread(check_deployer_watch, dw_id)
    if res.get("scan_ids"):
        from ..core.scanner import manager
        for sid in res["scan_ids"]:
            manager.start_scan(sid)
    return res


def _deployer_dict(d: DeployerWatch) -> dict:
    return {
        "id": d.id, "deployer_address": d.deployer_address, "chain": d.chain,
        "label": d.label, "enabled": d.enabled, "scan_profile": d.scan_profile,
        "interval_seconds": d.interval_seconds, "last_block_checked": d.last_block_checked,
        "deployed_count": d.deployed_count, "last_checked_at": d.last_checked_at,
        "created_at": d.created_at,
    }


def _watch_dict(w: WatchTarget) -> dict:
    return {
        "id": w.id, "address": w.address, "chain": w.chain, "label": w.label,
        "enabled": w.enabled, "scan_profile": w.scan_profile,
        "interval_seconds": w.interval_seconds, "github_url": w.github_url,
        "impl_address": w.impl_address, "codehash": w.codehash,
        "admin": w.admin, "owner": w.owner,
        "last_checked_at": w.last_checked_at, "last_change_at": w.last_change_at,
        "last_scan_id": w.last_scan_id, "created_at": w.created_at,
    }
