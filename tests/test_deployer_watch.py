"""Test the new-deployment watcher: a watched deployer ships a new contract ->
it is auto-onboarded as a WatchTarget, a rescan is created, the NEW_DEPLOY event
is recorded, already-known contracts are deduped, and the block pointer advances.
Etherscan is faked (no network).
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_deployer_watch.py -q
"""
from eth_utils import to_checksum_address
from sqlalchemy import select

from backend.core import monitor
from backend.database import SessionLocal, init_db
from backend.models import DeployerWatch, Scan, WatchEvent, WatchKind, WatchTarget

_KNOWN = "0x" + "11" * 20
_NEW = "0x" + "22" * 20


def test_deployer_onboards_new_and_dedupes(monkeypatch):
    init_db()
    with SessionLocal() as db:
        dw = DeployerWatch(deployer_address="0x" + "de" * 20, chain="ethereum",
                           scan_profile="defi-deep")
        db.add(dw)
        db.commit()
        db.refresh(dw)
        dwid = dw.id
        db.add(WatchTarget(address=to_checksum_address(_KNOWN), chain="ethereum"))
        db.commit()

    def fake_creations(_deployer, _chain, _start_block):
        return [(_KNOWN.lower(), 100), (_NEW.lower(), 105)]

    monkeypatch.setattr(monitor, "fetch_deployer_creations", fake_creations)

    res = monitor.check_deployer_watch(dwid)
    assert res["new"] == 1                       # only the genuinely-new contract
    assert len(res["scan_ids"]) == 1
    assert to_checksum_address(_NEW) in res["onboarded"]

    with SessionLocal() as db:
        wts = {w.address.lower() for w in db.scalars(select(WatchTarget))}
        assert _NEW.lower() in wts               # onboarded for ongoing upgrade-watching
        assert any(e.kind == WatchKind.NEW_DEPLOY for e in db.scalars(select(WatchEvent)))
        assert db.get(Scan, res["scan_ids"][0]) is not None
        dw2 = db.get(DeployerWatch, dwid)
        assert dw2.last_block_checked == 105 and dw2.deployed_count == 1

        # cleanup
        for w in db.scalars(select(WatchTarget)).all():
            if w.address.lower() in (_KNOWN.lower(), _NEW.lower()):
                db.delete(w)
        for sid in res["scan_ids"]:
            sc = db.get(Scan, sid)
            if sc:
                db.delete(sc)
        db.delete(db.get(DeployerWatch, dwid))
        db.commit()
