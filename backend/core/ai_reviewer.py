"""DeepSeek AI triage reviewer (OpenAI-compatible chat completions).

Sends a COMPACT structured evidence packet (not raw repos) and parses a strict
JSON verdict. Enforces a hard guardrail: the AI may not return CONFIRMED_CRITICAL
unless the evidence already demonstrates an unauthorized path (open on-chain role,
unguarded selector, or a passing fork/eth_call PoC). Otherwise it is downgraded
to LIKELY_CRITICAL_NEEDS_POC. Raw prompt + raw response are always stored.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ..config import ROOT_DIR, get_settings
from ..models import Classification

logger = logging.getLogger("bulkauditai.ai")

PROMPT_PATH = ROOT_DIR / "backend" / "prompts" / "deepseek_triage_prompt.md"

_FALLBACK_SYSTEM_PROMPT = """You are a strict smart contract security triage reviewer.
Classify the finding as exactly one of: CONFIRMED_CRITICAL, LIKELY_CRITICAL_NEEDS_POC,
NEEDS_MORE_INVESTIGATION, LOW_OR_INFO, FALSE_POSITIVE. Be strict: most candidates are
false positives or need more investigation. Do not classify governance/admin power as a
bug unless there is unauthorized access, a public role, a role mismatch, or a bypass.
Return ONLY JSON with keys: classification, severity, confidence, rationale, why_not_higher,
next_tests, reportability."""


@dataclass
class AIResult:
    classification: str | None = None
    severity: str | None = None
    confidence: float | None = None
    rationale: str = ""
    why_not_higher: str = ""
    next_tests: list[str] = field(default_factory=list)
    reportability: str = "needs_more_testing"
    model: str = ""
    prompt_text: str = ""
    request_json: dict = field(default_factory=dict)
    response_json: dict = field(default_factory=dict)
    error: str | None = None
    enforced_downgrade: bool = False


def _load_system_prompt() -> str:
    if PROMPT_PATH.exists():
        try:
            return PROMPT_PATH.read_text(encoding="utf-8")
        except OSError:
            pass
    return _FALLBACK_SYSTEM_PROMPT


def _extract_json(content: str) -> dict | None:
    if not content:
        return None
    # Strip markdown fences if present.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if fenced:
        content = fenced.group(1)
    # Otherwise grab the first {...} block.
    if not content.strip().startswith("{"):
        brace = re.search(r"(\{.*\})", content, re.DOTALL)
        if brace:
            content = brace.group(1)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def _normalize_classification(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip().upper().replace(" ", "_")
    return v if v in Classification.ALL else None


def evidence_has_unauthorized_path(packet: dict) -> bool:
    """Does the packet already demonstrate an unauthorized/reproducible path?"""
    ev = packet.get("evidence", {}) or {}
    onchain = packet.get("onchain_checks", {}) or {}
    if ev.get("poc_passed") or onchain.get("poc_passed"):
        return True
    if ev.get("open_roles") or ev.get("zero_address_has_role") or ev.get("dead_address_has_role"):
        return True
    if ev.get("unguarded"):
        return True
    if ev.get("user_controlled_target_or_data") and ev.get("has_access_control") is False:
        return True
    return False


def review_finding(packet: dict, *, prompt_save_path: Path | None = None) -> AIResult:
    s = get_settings()
    system_prompt = _load_system_prompt()
    user_content = json.dumps(packet, indent=2, default=str)
    result = AIResult(model=s.deepseek_model, prompt_text=system_prompt)

    if not s.enable_deepseek:
        result.error = "DeepSeek disabled (ENABLE_DEEPSEEK=false)"
        return result
    if not s.deepseek_api_key:
        result.error = "DEEPSEEK_API_KEY not configured"
        return result

    request_body = {
        "model": s.deepseek_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.0,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    result.request_json = {"messages_preview": packet, "model": s.deepseek_model}

    if prompt_save_path is not None:
        try:
            prompt_save_path.write_text(
                system_prompt + "\n\n=== USER PACKET ===\n" + user_content, encoding="utf-8"
            )
        except OSError:
            pass

    try:
        with httpx.Client(timeout=120) as client:
            resp = client.post(
                f"{s.deepseek_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {s.deepseek_api_key}"},
                json=request_body,
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        result.error = f"DeepSeek request failed: {type(exc).__name__}: {exc}"
        return result

    result.response_json = data
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        result.error = "unexpected DeepSeek response shape"
        return result

    parsed = _extract_json(content)
    if parsed is None:
        result.error = "could not parse JSON verdict from model output"
        result.rationale = content[:2000]
        return result

    cls = _normalize_classification(parsed.get("classification"))
    result.classification = cls or Classification.NEEDS_MORE_INVESTIGATION
    result.severity = parsed.get("severity")
    try:
        result.confidence = float(parsed.get("confidence")) if parsed.get("confidence") is not None else None
    except (TypeError, ValueError):
        result.confidence = None
    result.rationale = str(parsed.get("rationale", ""))[:4000]
    result.why_not_higher = str(parsed.get("why_not_higher", ""))[:2000]
    nt = parsed.get("next_tests", [])
    result.next_tests = nt if isinstance(nt, list) else [str(nt)]
    result.reportability = str(parsed.get("reportability", "needs_more_testing"))

    # --- Hard guardrail: no CONFIRMED_CRITICAL without a demonstrated path --- #
    if result.classification == Classification.CONFIRMED_CRITICAL and not evidence_has_unauthorized_path(
        packet
    ):
        result.classification = Classification.LIKELY_CRITICAL_NEEDS_POC
        result.enforced_downgrade = True
        result.why_not_higher = (
            "[enforced] No reproducible unauthorized path (open role / unguarded selector / "
            "PoC) in evidence; downgraded from CONFIRMED_CRITICAL. " + result.why_not_higher
        )

    return result
