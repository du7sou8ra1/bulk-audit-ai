"""Tests for the monitoring ("before-drain") layer.

Covers the pure helpers, alerting no-op, and an integration test of
`check_watch_target` with a FAKED chain that reports an implementation upgrade —
asserting it records an UPGRADE event, creates a rescan Scan, and updates the
diff baseline. No network/RPC.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_monitor.py -q
"""
import datetime as dt
from types import SimpleNamespace

from sqlalchemy import select

from backend.core import alerting, monitor
from backend.database import SessionLocal, init_db
from backend.models import Scan, WatchEvent, WatchKind, WatchTarget


def test_codehash():
    assert monitor._codehash(None) is None
    assert monitor._codehash("0x") is None
    h = monitor._codehash("0x6001600155")
    assert h and h.startswith("0x") and len(h) == 66


def test_due():
    now = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.timezone.utc)
    assert monitor._due(None, 300, now) is True
    assert monitor._due(now - dt.timedelta(seconds=10), 300, now) is False
    assert monitor._due(now - dt.timedelta(seconds=400), 300, now) is True


def test_alerting_noop_without_webhook():
    # default config has no ALERT_WEBHOOK_URL -> send_alert is a no-op returning False
    assert alerting.send_alert("test", "body", severity="critical") is False


def test_check_detects_upgrade(monkeypatch):
    init_db()
    with SessionLocal() as db:
        w = WatchTarget(
            address="0x000000000000000000000000000000000000aBcD",
            chain="ethereum", scan_profile="defi-deep",
            impl_address="0x1111111111111111111111111111111111111111",
            last_checked_at=dt.datetime(2020, 1, 1),
        )
        db.add(w)
        db.commit()
        db.refresh(w)
        wid = w.id

    class FakeOnchain:
        available = True
        def __init__(self, *a, **k):
            pass
        def get_code(self, _a):
            return "0x600160015560"

    def fake_resolve(_onchain, _address, _abi, _impl):
        return SimpleNamespace(
            implementation="0x2222222222222222222222222222222222222222",
            admin=None, admin_owner=None, owner=None, is_proxy=True,
        )

    monkeypatch.setattr(monitor, "OnchainClient", FakeOnchain)
    monkeypatch.setattr(monitor, "resolve_proxy", fake_resolve)

    res = monitor.check_watch_target(wid)
    assert res["changed"] is True
    assert res["scan_id"] is not None
    assert WatchKind.UPGRADE in res["events"]

    with SessionLocal() as db:
        w2 = db.get(WatchTarget, wid)
        assert w2.impl_address == "0x2222222222222222222222222222222222222222"
        evs = db.scalars(select(WatchEvent).where(WatchEvent.watch_target_id == wid)).all()
        assert any(e.kind == WatchKind.UPGRADE for e in evs)
        assert db.get(Scan, res["scan_id"]) is not None
        # cleanup
        db.delete(db.get(Scan, res["scan_id"]))
        db.delete(db.get(WatchTarget, wid))
        db.commit()


def test_first_seen_is_baseline_not_change(monkeypatch):
    init_db()
    with SessionLocal() as db:
        w = WatchTarget(address="0x000000000000000000000000000000000000bEEf",
                        chain="ethereum", scan_profile="defi-deep")  # last_checked_at = None
        db.add(w)
        db.commit()
        db.refresh(w)
        wid = w.id

    class FakeOnchain:
        available = True
        def __init__(self, *a, **k):
            pass
        def get_code(self, _a):
            return "0x6001"

    def fake_resolve(_o, _a, _b, _i):
        return SimpleNamespace(implementation="0x3333333333333333333333333333333333333333",
                               admin=None, admin_owner=None, owner=None, is_proxy=True)

    monkeypatch.setattr(monitor, "OnchainClient", FakeOnchain)
    monkeypatch.setattr(monitor, "resolve_proxy", fake_resolve)

    res = monitor.check_watch_target(wid)
    assert res["changed"] is False and res["scan_id"] is None  # first observation = baseline
    with SessionLocal() as db:
        w2 = db.get(WatchTarget, wid)
        assert w2.impl_address == "0x3333333333333333333333333333333333333333"
        db.delete(db.get(WatchTarget, wid))
        db.commit()
