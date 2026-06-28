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

from ..config import ROOT_DIR, get_settings
from ..models import Classification
from .llm import chat_json

logger = logging.getLogger("bulkauditai.ai")

PROMPT_PATH = ROOT_DIR / "backend" / "prompts" / "deepseek_triage_prompt.md"

_FALLBACK_SYSTEM_PROMPT = """You are a strict smart contract security triage reviewer.
Classify the finding as exactly one of: CONFIRMED_CRITICAL, LIKELY_CRITICAL_NEEDS_POC,
NEEDS_MORE_INVESTIGATION, LOW_OR_INFO, FALSE_POSITIVE. Be strict: most candidates are
false positives or need more investigation. Do not classify governance/admin power as a
bug unless there is unauthorized access, a public role, a role mismatch, or a bypass.
Historical audit-corpus matches are precedent/context only, never proof of target
exploitability.
Return ONLY JSON with keys: classification, severity, confidence, rationale, why_not_higher,
next_tests, reportability."""

_ULTRA_REVIEW_ADDENDUM = """

ULTRA REVIEW MODE:
Before returning the final JSON, privately run a deeper audit checklist:
1. Trace the claimed exploit path from entrypoint to value/state impact.
2. Identify every caller/role/proxy/admin assumption needed by the attack.
3. Look for concrete on-chain defusing controls: modifiers, require checks,
   equality/range checks, hash/commitment binding, allowlists, nullifiers, or
   replay markers.
4. Compare against tool corroboration and detector evidence. If a high-impact
   deterministic/corroborated finding is not concretely defused, uncertainty
   must become NEEDS_MORE_INVESTIGATION, not FALSE_POSITIVE.
5. Suggest the smallest fork/read-only test that would settle the question.

Do not reveal hidden reasoning steps. Return only the required concise JSON."""


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


def _system_prompt_for_mode(mode: str) -> str:
    prompt = _load_system_prompt()
    if (mode or "").strip().lower() in {"deep", "ultra", "ultrathinking", "ultra-thinking"}:
        prompt += _ULTRA_REVIEW_ADDENDUM
    return prompt


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


def _has_concrete_defusing_control(ev: dict) -> bool:
    refutation = ev.get("refutation") or {}
    if ev.get("suppressed"):
        return True
    return bool(
        ev.get("refuted_concrete")
        or refutation.get("concrete_mitigation")
        or refutation.get("concrete_defusing_control")
    )


def _is_high_signal_packet(packet: dict) -> bool:
    ev = packet.get("evidence", {}) or {}
    cand = packet.get("candidate", {}) or {}
    tier = ev.get("onchain_detectable")
    protected = bool(ev.get("lead_only") or tier in ("lead_only", "confirmable"))
    if protected or ev.get("corroborated"):
        return True
    try:
        impact = float(cand.get("pre_ai_impact") or 0)
        confidence = float(cand.get("pre_ai_confidence") or 0)
    except (TypeError, ValueError):
        impact = confidence = 0.0
    pre_cls = str(cand.get("pre_ai_classification") or "")
    return bool(
        impact >= 8
        and confidence >= 4
        and pre_cls
        in {
            Classification.NEEDS_MORE_INVESTIGATION,
            Classification.LIKELY_CRITICAL_NEEDS_POC,
            Classification.CONFIRMED_CRITICAL,
        }
    )


def _apply_post_triage_guardrails(packet: dict, result: AIResult) -> None:
    """Conservative AI floor: do not let AI bury strong unresolved leads."""
    ev = packet.get("evidence", {}) or {}

    # No CONFIRMED_CRITICAL without demonstrated unauthorized path.
    if result.classification == Classification.CONFIRMED_CRITICAL and not evidence_has_unauthorized_path(
        packet
    ):
        result.classification = Classification.LIKELY_CRITICAL_NEEDS_POC
        result.enforced_downgrade = True
        result.why_not_higher = (
            "[enforced] No reproducible unauthorized path (open role / unguarded selector / "
            "PoC) in evidence; downgraded from CONFIRMED_CRITICAL. " + result.why_not_higher
        )

    # A high-signal deterministic/corroborated finding is not allowed to become
    # FALSE_POSITIVE/LOW_OR_INFO unless evidence cites a concrete defusing control.
    if (
        _is_high_signal_packet(packet)
        and not _has_concrete_defusing_control(ev)
        and result.classification in (Classification.FALSE_POSITIVE, Classification.LOW_OR_INFO)
    ):
        result.classification = Classification.NEEDS_MORE_INVESTIGATION
        result.enforced_downgrade = True
        result.reportability = "needs_more_testing"
        result.why_not_higher = (
            "[enforced] high-signal detector/corroborated finding was not concretely "
            "defused by an on-chain control; floored to NEEDS_MORE_INVESTIGATION. "
            + result.why_not_higher
        )


def review_finding(packet: dict, *, prompt_save_path: Path | None = None) -> AIResult:
    s = get_settings()
    system_prompt = _system_prompt_for_mode(s.ai_review_mode)
    user_content = json.dumps(packet, indent=2, default=str)
    result = AIResult(model=s.deepseek_model, prompt_text=system_prompt)

    if not s.enable_deepseek:
        result.error = "DeepSeek disabled (ENABLE_DEEPSEEK=false)"
        return result
    if not s.deepseek_api_key:
        result.error = "DEEPSEEK_API_KEY not configured"
        return result

    result.request_json = {
        "messages_preview": packet,
        "model": s.deepseek_model,
        "ai_review_mode": s.ai_review_mode,
    }

    if prompt_save_path is not None:
        try:
            prompt_save_path.write_text(
                system_prompt + "\n\n=== USER PACKET ===\n" + user_content, encoding="utf-8"
            )
        except OSError:
            pass

    chat = chat_json(system_prompt, user_content, timeout=s.ai_timeout_seconds)
    result.request_json.update(chat.request_json or {})
    result.response_json = chat.response_json
    result.model = chat.model or result.model
    if chat.error:
        result.error = chat.error
        result.rationale = chat.raw_content[:2000]
        return result

    parsed = chat.parsed or _extract_json(chat.raw_content)
    if parsed is None:
        result.error = "could not parse JSON verdict from model output"
        result.rationale = chat.raw_content[:2000]
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

    _apply_post_triage_guardrails(packet, result)

    return result
