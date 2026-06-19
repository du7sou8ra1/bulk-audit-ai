"""Outbound alerting (webhook) for the monitoring layer.

A confirmed critical or a detected upgrade must reach a human FAST — that is the
whole point of "before drain". This posts a compact message to a configured
webhook (Slack/Discord-compatible via `text`/`content`, or any generic JSON
endpoint). No-op when `ALERT_WEBHOOK_URL` is unset.

This is a NOTIFICATION only — it never auto-submits a report or contacts a
protocol. Disclosure stays human-gated.
"""
from __future__ import annotations

import logging

import httpx

from ..config import get_settings

logger = logging.getLogger("bulkauditai.alerting")

_EMOJI = {"critical": "🔴", "high": "🟠", "warning": "🟡", "info": "🔵"}


def alerts_enabled() -> bool:
    return bool(get_settings().alert_webhook_url)


def send_alert(title: str, body: str = "", *, severity: str = "warning",
               context: dict | None = None) -> bool:
    """Post an alert to the configured webhook. Returns True on a 2xx, else False."""
    s = get_settings()
    url = s.alert_webhook_url
    if not url:
        return False
    emoji = _EMOJI.get(severity, "🔔")
    text = f"{emoji} *BulkAuditAI* [{severity.upper()}] {title}"
    if body:
        text += f"\n{body}"
    # Slack uses `text`, Discord uses `content`; include both + structured fields.
    payload = {"text": text, "content": text, "severity": severity,
               "title": title, "body": body, **(context or {})}
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, json=payload)
        ok = 200 <= resp.status_code < 300
        if not ok:
            logger.warning("alert webhook returned HTTP %s", resp.status_code)
        return ok
    except Exception as exc:  # noqa: BLE001
        logger.warning("alert webhook failed: %s", exc)
        return False
