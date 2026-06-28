"""Regression test: starting a scan from a SYNC endpoint (threadpool worker, no
running loop) must schedule onto the captured main loop, not raise
'no running event loop'.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_scan_manager.py -q
"""
import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from backend.api import scans as scan_api
from backend.core.scanner import _finding_slug, manager
from backend.database import SessionLocal, init_db
from backend.models import Scan, ScanStatus, Target


def test_finding_slug_is_path_safe():
    # the LLM reasoner can return a function name containing '/' and spaces, which
    # must NOT leak into the evidence/AI file path (this crashed a real scan).
    s = _finding_slug("invariant_reasoner", 6, "processRollup / processRollupProof")
    assert "/" not in s and " " not in s
    assert s == "invariant_reasoner_6_processRollup___processRollupProof"
    assert _finding_slug("zk_verifier", 0, None) == "zk_verifier_0_x"


def test_start_scan_from_worker_thread(monkeypatch):
    ran: list[int] = []

    async def fake_run(scan_id: int) -> None:
        ran.append(scan_id)

    monkeypatch.setattr(manager, "_run_scan", fake_run)

    async def runner() -> None:
        manager.set_loop(asyncio.get_running_loop())
        # Simulate the sync FastAPI endpoint: call start_scan from a worker thread.
        await asyncio.to_thread(manager.start_scan, 12345)
        await asyncio.sleep(0.1)  # let call_soon_threadsafe spawn the task
        assert 12345 in manager._tasks
        await asyncio.sleep(0.05)
        assert 12345 in ran
        manager._tasks.pop(12345, None)

    asyncio.run(runner())


def test_rescan_clones_failed_scan_and_starts_new_job(monkeypatch):
    init_db()
    started: list[int] = []
    monkeypatch.setattr(scan_api.manager, "start_scan", lambda scan_id: started.append(scan_id))

    with SessionLocal() as db:
        old = Scan(
            name="broken audit",
            chain="polygon",
            scan_profile="ultra-deep-v2",
            toggles={"slither": True, "fuzzing": True},
            total_targets=2,
            status=ScanStatus.FAILED,
            error="tool crashed",
        )
        db.add(old)
        db.commit()
        db.refresh(old)
        db.add_all(
            [
                Target(
                    scan_id=old.id,
                    address="0x1111111111111111111111111111111111111111",
                    chain="polygon",
                    label="aztec-a",
                ),
                Target(
                    scan_id=old.id,
                    address="0x2222222222222222222222222222222222222222",
                    chain="polygon",
                    label="aztec-b",
                ),
            ]
        )
        db.commit()

        try:
            out = scan_api.rescan_scan(old.id, db)
            assert started == [out.id]
            assert out.id != old.id
            assert out.status == ScanStatus.QUEUED
            assert out.chain == old.chain
            assert out.scan_profile == old.scan_profile
            assert out.toggles == old.toggles
            assert out.total_targets == 2
            assert out.name == f"Rescan of #{old.id}: broken audit"

            cloned = db.scalars(
                select(Target).where(Target.scan_id == out.id).order_by(Target.id)
            ).all()
            assert [(t.address, t.chain, t.label) for t in cloned] == [
                ("0x1111111111111111111111111111111111111111", "polygon", "aztec-a"),
                ("0x2222222222222222222222222222222222222222", "polygon", "aztec-b"),
            ]
        finally:
            if started:
                db.delete(db.get(Scan, started[0]))
            db.delete(db.get(Scan, old.id))
            db.commit()


def test_rescan_rejects_non_failed_or_cancelled_scan(monkeypatch):
    init_db()
    monkeypatch.setattr(scan_api.manager, "start_scan", lambda _scan_id: None)

    with SessionLocal() as db:
        scan = Scan(
            name="healthy audit",
            chain="ethereum",
            scan_profile="deep",
            total_targets=1,
            status=ScanStatus.COMPLETED,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        try:
            with pytest.raises(HTTPException) as exc:
                scan_api.rescan_scan(scan.id, db)
            assert exc.value.status_code == 400
            assert "failed or cancelled" in exc.value.detail
        finally:
            db.delete(db.get(Scan, scan.id))
            db.commit()
