"""Shared LLM client (OpenAI-compatible chat completions, e.g. DeepSeek).

`ai_reviewer.py` historically inlined its own HTTP call for the *triage* step.
The new semantic-reasoning (`invariant_reasoner`) and adversarial-refutation
(`refuter`) layers need the same plumbing, so it is factored out here once:
strict JSON-mode request, a no-json-mode retry for providers that reject
`response_format`, bounded timeout, and defensive JSON extraction.

This module performs READ-ONLY reasoning over already-fetched source/evidence.
It never touches a chain, a key store, or the filesystem beyond what the caller
passes in.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

import httpx

from ..config import get_settings

logger = logging.getLogger("bulkauditai.llm")


@dataclass
class ChatResult:
    parsed: dict | None = None          # parsed JSON object (None on failure)
    raw_content: str = ""               # raw assistant text
    response_json: dict = field(default_factory=dict)
    model: str = ""
    error: str | None = None


def _extract_json(content: str) -> dict | None:
    if not content:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if fenced:
        content = fenced.group(1)
    if not content.strip().startswith("{"):
        brace = re.search(r"(\{.*\})", content, re.DOTALL)
        if brace:
            content = brace.group(1)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def chat_json(
    system_prompt: str,
    user_payload: str | dict,
    *,
    temperature: float = 0.0,
    timeout: int = 180,
    max_tokens: int | None = None,
) -> ChatResult:
    """One JSON-returning chat round-trip. Always returns a ChatResult; never raises."""
    s = get_settings()
    res = ChatResult(model=s.deepseek_model)

    if not s.enable_deepseek:
        res.error = "LLM disabled (ENABLE_DEEPSEEK=false)"
        return res
    if not s.deepseek_api_key:
        res.error = "DEEPSEEK_API_KEY not configured"
        return res

    user_content = user_payload if isinstance(user_payload, str) else json.dumps(
        user_payload, indent=2, default=str
    )
    body = {
        "model": s.deepseek_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": temperature,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    if max_tokens:
        body["max_tokens"] = max_tokens

    url = f"{s.deepseek_base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {s.deepseek_api_key}",
        "HTTP-Referer": "https://github.com/bulk-audit-ai",
        "X-Title": "BulkAuditAI",
    }

    def _post(payload: dict) -> dict:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            return resp.json()

    try:
        data = _post(body)
    except httpx.HTTPStatusError as exc:
        # Some providers reject response_format -> retry once without it.
        if 400 <= exc.response.status_code < 500 and "response_format" in body:
            body2 = {k: v for k, v in body.items() if k != "response_format"}
            try:
                data = _post(body2)
            except Exception as exc2:  # noqa: BLE001
                res.error = f"LLM request failed: {type(exc2).__name__}: {exc2}"
                return res
        else:
            res.error = f"LLM HTTP {exc.response.status_code}: {exc.response.text[:300]}"
            return res
    except Exception as exc:  # noqa: BLE001
        res.error = f"LLM request failed: {type(exc).__name__}: {exc}"
        return res

    res.response_json = data
    try:
        res.raw_content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        res.error = "unexpected LLM response shape"
        return res

    res.parsed = _extract_json(res.raw_content)
    if res.parsed is None:
        res.error = "could not parse JSON from model output"
    return res


def llm_available() -> bool:
    s = get_settings()
    return bool(s.enable_deepseek and s.deepseek_api_key)
