"""WebSocket live-progress endpoint: ws://<host>/ws/scans/{scan_id}."""
from __future__ import annotations

import asyncio
import contextlib

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.scanner import hub

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: int) -> None:
    await websocket.accept()
    queue = hub.subscribe(scan_id)
    await websocket.send_json({"type": "connected", "scan_id": scan_id})
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=20)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                # heartbeat so proxies don't drop the idle socket
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hub.unsubscribe(scan_id, queue)
        with contextlib.suppress(Exception):
            await websocket.close()
