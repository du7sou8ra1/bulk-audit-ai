"""Continuous monitoring — the "before-drain" layer.

A one-shot scanner can't catch a bug shipped tomorrow. This watches a list of
funded contracts and, on the highest-signal "audit NOW" triggers, auto-fires a
fresh scan and alerts:

  * EIP-1967 implementation slot changed  -> an upgrade (Aztec/Wasabi were upgrades)
  * the address's own bytecode changed     -> metamorphic redeploy
  * admin / owner changed                  -> governance takeover surface

`check_watch_target()` is blocking (on-chain reads + DB) and is run in a thread by
the async `WatchManager` loop; it records events, creates the rescan rows, sends
alerts, and updates the diff baseline — but does NOT start the scan task (that
needs the event loop), so the loop starts it after the thread returns.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging

from eth_utils import keccak, to_checksum_address
from sqlalchemy import select

from ..config import get_settings
from ..database import SessionLocal
from ..models import (
    DeployerWatch,
    Scan,
    ScanStatus,
    Target,
    WatchEvent,
    WatchKind,
    WatchTarget,
    utcnow,
)
from . import alerting
from .onchain import OnchainClient
from .proxy_resolver import resolve_proxy
from .source_fetcher import fetch_deployer_creations

logger = logging.getLogger("bulkauditai.monitor")


def _codehash(code: str | None) -> str | None:
    if not code or code in ("0x", "0x0", ""):
        return None
    try:
        return "0x" + keccak(hexstr=code).hex()
    except Exception:  # noqa: BLE001
        return None


def _create_rescan(address: str, chain: str, profile: str, reason: str) -> int:
    with SessionLocal() as db:
        scan = Scan(
            name=f"monitor: {reason} {address[:10]}",
            chain=chain, scan_profile=profile, total_targets=1,
            status=ScanStatus.QUEUED, toggles={},
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        db.add(Target(scan_id=scan.id, address=address, chain=chain, label="monitor-rescan"))
        db.commit()
        return scan.id


def check_watch_target(watch_id: int) -> dict:
    """Blocking change-check for one watch target. Returns {changed, scan_id, events}."""
    with SessionLocal() as db:
        w = db.get(WatchTarget, watch_id)
        if w is None or not w.enabled:
            return {"changed": False, "scan_id": None, "events": []}
        address, chain, profile = w.address, w.chain, w.scan_profile
        prev = {"impl": w.impl_address, "codehash": w.codehash,
                "admin": w.admin, "owner": w.owner}
        first_seen = w.last_checked_at is None

    onchain = OnchainClient(chain=chain)
    if not onchain.available:
        _record_event(watch_id, WatchKind.CHECK_ERROR, {"error": "rpc unavailable"})
        return {"changed": False, "scan_id": None, "events": ["check_error"]}

    code = onchain.get_code(address)
    codehash = _codehash(code)
    try:
        proxy = resolve_proxy(onchain, address, None, None)
        impl = proxy.implementation
        admin = proxy.admin
        owner = proxy.admin_owner or proxy.owner
    except Exception as exc:  # noqa: BLE001
        logger.warning("proxy resolve failed for %s: %s", address, exc)
        impl = admin = owner = None

    events: list[tuple[str, dict, str]] = []  # (kind, detail, severity)
    rescan_reason = None
    if not first_seen:
        if prev["impl"] and impl and impl.lower() != (prev["impl"] or "").lower():
            events.append((WatchKind.UPGRADE,
                           {"old": prev["impl"], "new": impl}, "critical"))
            rescan_reason = "upgrade"
        # codehash change only matters for non-proxy (proxy bytecode is fixed)
        if impl is None and prev["codehash"] and codehash and codehash != prev["codehash"]:
            events.append((WatchKind.CODEHASH_CHANGE,
                           {"old": prev["codehash"], "new": codehash}, "critical"))
            rescan_reason = rescan_reason or "codehash"
        if prev["admin"] and admin and admin.lower() != (prev["admin"] or "").lower():
            events.append((WatchKind.ADMIN_CHANGE, {"old": prev["admin"], "new": admin}, "high"))
        if prev["owner"] and owner and owner.lower() != (prev["owner"] or "").lower():
            events.append((WatchKind.OWNER_CHANGE, {"old": prev["owner"], "new": owner}, "high"))

    scan_id = None
    if rescan_reason:
        scan_id = _create_rescan(address, chain, profile, rescan_reason)

    # persist events + send alerts + update the baseline
    for kind, detail, severity in events:
        _record_event(watch_id, kind, detail, scan_id=scan_id)
        alerting.send_alert(
            f"{kind} on {address}",
            f"{detail.get('old')} -> {detail.get('new')}"
            + (f" — rescan #{scan_id} started" if scan_id else ""),
            severity=severity, context={"address": address, "chain": chain, "kind": kind},
        )

    now = utcnow()
    with SessionLocal() as db:
        w = db.get(WatchTarget, watch_id)
        if w is not None:
            w.impl_address = impl or w.impl_address
            w.codehash = codehash or w.codehash
            w.admin = admin or w.admin
            w.owner = owner or w.owner
            w.last_checked_at = now
            if events:
                w.last_change_at = now
            if scan_id:
                w.last_scan_id = scan_id
            db.commit()

    return {"changed": bool(events), "scan_id": scan_id,
            "events": [e[0] for e in events]}


def _record_event(watch_id: int, kind: str, detail: dict, scan_id: int | None = None) -> None:
    with SessionLocal() as db:
        db.add(WatchEvent(watch_target_id=watch_id, kind=kind, detail=detail, scan_id=scan_id))
        db.commit()


def check_deployer_watch(deployer_watch_id: int) -> dict:
    """Blocking: find contracts a watched deployer shipped; onboard + rescan each new one."""
    with SessionLocal() as db:
        dw = db.get(DeployerWatch, deployer_watch_id)
        if dw is None or not dw.enabled:
            return {"new": 0, "scan_ids": [], "onboarded": []}
        deployer, chain, profile = dw.deployer_address, dw.chain, dw.scan_profile
        start_block = dw.last_block_checked or 0
        known = {w.address.lower() for w in db.scalars(select(WatchTarget))}

    try:
        creations = fetch_deployer_creations(deployer, chain, start_block)
    except Exception as exc:  # noqa: BLE001
        logger.warning("deployer creation fetch failed for %s: %s", deployer, exc)
        _record_event_deployer(deployer_watch_id, WatchKind.CHECK_ERROR, {"error": str(exc)[:200]})
        return {"new": 0, "scan_ids": [], "onboarded": []}

    cap = get_settings().max_new_deploys_per_check
    onboarded: list[str] = []
    scan_ids: list[int] = []
    last_onboarded_block: int | None = None

    for addr, block in creations:  # ascending by block
        if addr in known:
            continue
        if len(onboarded) >= cap:
            break  # remaining (higher blocks) get picked up next cycle
        try:
            cs = to_checksum_address(addr)
        except Exception:  # noqa: BLE001
            cs = addr
        with SessionLocal() as db:
            wt = WatchTarget(address=cs, chain=chain, scan_profile=profile,
                             label=f"auto: deployed by {deployer[:10]}")
            db.add(wt)
            db.commit()
            db.refresh(wt)
            wt_id = wt.id
        scan_id = _create_rescan(cs, chain, profile, "new-deploy")
        scan_ids.append(scan_id)
        _record_event(wt_id, WatchKind.NEW_DEPLOY,
                      {"deployer": deployer, "block": block}, scan_id=scan_id)
        onboarded.append(cs)
        known.add(addr)
        last_onboarded_block = block
        alerting.send_alert(
            f"New contract from watched deployer {deployer[:10]}",
            f"{cs} (block {block}) — onboarded + rescan #{scan_id} started",
            severity="high", context={"address": cs, "deployer": deployer, "chain": chain})

    with SessionLocal() as db:
        dw = db.get(DeployerWatch, deployer_watch_id)
        if dw is not None:
            if last_onboarded_block is not None:
                # re-fetch from this block next time (dedupe skips already-onboarded)
                dw.last_block_checked = last_onboarded_block
            elif creations:
                dw.last_block_checked = creations[-1][1]  # all already known -> advance
            dw.deployed_count = (dw.deployed_count or 0) + len(onboarded)
            dw.last_checked_at = utcnow()
            db.commit()

    return {"new": len(onboarded), "scan_ids": scan_ids, "onboarded": onboarded}


def _record_event_deployer(dw_id: int, kind: str, detail: dict) -> None:
    # deployer errors aren't tied to a WatchTarget; log + best-effort alert only.
    logger.info("deployer-watch %s: %s %s", dw_id, kind, detail)


def _due(last_checked: dt.datetime | None, interval: int, now: dt.datetime) -> bool:
    if last_checked is None:
        return True
    lc = last_checked if last_checked.tzinfo else last_checked.replace(tzinfo=dt.timezone.utc)
    return (now - lc).total_seconds() >= interval


class WatchManager:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("monitor started")

    def stop(self) -> None:
        self._running = False
        logger.info("monitor stopping")

    async def _loop(self) -> None:
        from .scanner import manager as scan_manager

        while self._running:
            try:
                now = utcnow()
                base_iv = get_settings().monitor_interval_seconds
                with SessionLocal() as db:
                    watches = db.scalars(
                        select(WatchTarget).where(WatchTarget.enabled.is_(True))
                    ).all()
                    due = [w.id for w in watches
                           if _due(w.last_checked_at, w.interval_seconds or base_iv, now)]
                for wid in due:
                    if not self._running:
                        break
                    res = await asyncio.to_thread(check_watch_target, wid)
                    if res.get("scan_id"):
                        scan_manager.start_scan(res["scan_id"])

                # New-deployment watchers: a watched deployer shipping a new contract.
                with SessionLocal() as db:
                    deployers = db.scalars(
                        select(DeployerWatch).where(DeployerWatch.enabled.is_(True))
                    ).all()
                    due_dw = [d.id for d in deployers
                              if _due(d.last_checked_at, d.interval_seconds or base_iv, now)]
                for did in due_dw:
                    if not self._running:
                        break
                    res = await asyncio.to_thread(check_deployer_watch, did)
                    for sid in res.get("scan_ids", []):
                        scan_manager.start_scan(sid)
            except Exception as exc:  # noqa: BLE001  - never let the loop die
                logger.exception("monitor loop error: %s", exc)
            await asyncio.sleep(max(15, min(get_settings().monitor_interval_seconds, 60)))


monitor = WatchManager()
