"""Regression test: starting a scan from a SYNC endpoint (threadpool worker, no
running loop) must schedule onto the captured main loop, not raise
'no running event loop'.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_scan_manager.py -q
"""
import asyncio

from backend.core.scanner import _finding_slug, manager


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
