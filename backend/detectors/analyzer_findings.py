"""Promote native analyzer findings (Slither / Mythril / Semgrep) to candidates.

The analyzers already run per target, but their results were consumed ONLY as
confidence corroboration for the custom detectors (`scoring._tool_agreement`). A
real bug that ONLY Slither/Mythril/Semgrep caught — and no custom detector
independently flagged — was silently discarded.

This adapter turns each analyzer finding into a `FindingCandidate` so it flows
through the SAME downstream pipeline as every other candidate (candidate_sanity,
the adversarial refuter, dedup, scoring, and the chain-attribution gate). That is
what keeps precision under control: these are not raw dumps, they are gated by the
same machinery. Slither's ~90 detectors and Mythril's symbolic SWC checks are
professionally tuned and low-FP, so this is a large recall gain at low FP cost.

Analyzer findings never auto-reach CONFIRMED_CRITICAL: confidence is capped so a
static/symbolic hit lands at LIKELY_CRITICAL_NEEDS_POC at most until a PoC or
on-chain evidence corroborates it.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext

# Slither checks that denote a direct fund-loss / takeover primitive -> impact 9.
_SLITHER_CRITICAL = {
    "reentrancy-eth",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "controlled-delegatecall",
    "unprotected-upgrade",
    "suicidal",
    "delegatecall-loop",
}
_IMPACT_WORD = {"critical": 9.0, "high": 8.0, "medium": 6.0, "low": 4.0, "informational": 2.5, "info": 2.5}
_CONF_WORD = {"high": 6.5, "medium": 5.0, "low": 3.5}
# Analyzer-alone can never reach CONFIRMED_CRITICAL (needs impact>=9 AND conf>=8).
_CONF_CAP = 7.0
_SOURCES = ("slither", "mythril", "semgrep", "aderyn")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:48] or "issue"


class AnalyzerFindingsDetector(Detector):
    name = "analyzer_findings"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        try:
            from ..config import get_settings
            if not getattr(get_settings(), "enable_analyzer_findings", True):
                return []
        except Exception:
            pass
        outputs = getattr(ctx, "tool_outputs", None)
        if not isinstance(outputs, dict):
            return []
        out: list[FindingCandidate] = []
        for source in _SOURCES:
            block = outputs.get(source)
            if not isinstance(block, dict):
                continue
            for f in block.get("findings") or []:
                if not isinstance(f, dict):
                    continue
                cand = self._adapt(source, f)
                if cand is not None:
                    out.append(cand)
        return out

    def _adapt(self, source: str, f: dict) -> FindingCandidate | None:
        check = str(f.get("check") or f.get("title") or "").strip()
        impact_word = str(f.get("impact") or "").lower()
        conf_word = str(f.get("confidence") or "").lower()
        description = str(f.get("description") or "").strip()
        location = str(f.get("location") or "")
        function = str(f.get("function") or "")
        high_value = bool(f.get("high_value"))
        if not check and not description:
            return None

        impact = _IMPACT_WORD.get(impact_word, 4.0)
        if source == "slither":
            if check in _SLITHER_CRITICAL:
                impact = 9.0
            elif high_value or impact_word == "high":
                impact = max(impact, 7.0)
        confidence = min(_CONF_WORD.get(conf_word, 4.0), _CONF_CAP)

        severity = (
            "critical" if impact >= 9
            else "high" if impact >= 7
            else "medium" if impact >= 4
            else "low"
        )
        label = check or _slug(description)
        title = f"[{source}] {label}"
        if function:
            title += f": {function}"

        evidence = {
            "source": source,
            "analyzer": source,
            "tool": source,
            "check": check,
            "bug_class": check or _slug(description),
            "description": description[:2000],
            "location": location,
            "external_analyzer": True,
            "needs_poc": True,
        }
        if function:
            evidence["function"] = function

        body = description or f"{source} flagged `{label}`."
        if location:
            body += f"\n\nReported by the {source} analyzer at {location}."

        return FindingCandidate(
            detector=f"{source}:{_slug(check) if check else 'issue'}",
            title=title,
            description=body[:2000],
            impact_score=impact,
            confidence_score=confidence,
            severity_candidate=severity,
            evidence=evidence,
            next_tests=[
                f"Review the {source} finding '{label}' and confirm exploitability with a read-only fork PoC",
            ],
            affected_functions=[function] if function else [],
        )
