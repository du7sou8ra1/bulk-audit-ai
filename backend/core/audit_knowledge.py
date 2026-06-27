"""Historical audit/bug-bounty corpus matching.

The corpus is generated from user-provided JSON archives and kept compact under
``backend/data/audit_knowledge.json``. It is not a classifier by itself; it adds
nearby real-world examples to evidence packets so AI/human triage has precedent
instead of relying on risky function names alone.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from ..detectors.base import FindingCandidate

CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "audit_knowledge.json"

_STOP = frozenset(
    "the and for with that this from into can not are was were will would should "
    "could because contract function external public issue vulnerability finding "
    "user users owner admin when where there have has had using use used same some "
    "only also lack missing incorrect wrong high medium low critical severity "
    "protocol impact attack vector code line file data value amount token tokens"
    .split()
)


@lru_cache(maxsize=1)
def load_corpus() -> dict:
    try:
        return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 0, "entry_count": 0, "entries": []}


def annotate_candidate(candidate: FindingCandidate, *, limit: int = 4) -> list[dict]:
    """Attach closest historical examples to ``candidate.evidence``.

    Matching is intentionally simple and deterministic: token overlap between
    candidate title/description/evidence/function names and pre-normalized
    corpus keywords. The result is supporting context, not proof.
    """
    corpus = load_corpus()
    entries = corpus.get("entries") or []
    query = _candidate_tokens(candidate)
    if not query or not entries:
        return []

    scored = []
    for entry in entries:
        kws = set(entry.get("keywords") or [])
        overlap = sorted(query & kws)
        if len(overlap) < 2:
            continue
        score = len(overlap)
        if str(entry.get("severity", "")).upper() == "CRITICAL":
            score += 1
        if candidate.detector.replace("_", "") in "".join(kws):
            score += 1
        scored.append((score, overlap, entry))

    scored.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
    matches = [
        {
            "id": entry.get("id"),
            "title": entry.get("title"),
            "severity": entry.get("severity"),
            "source": entry.get("source"),
            "source_file": entry.get("source_file"),
            "url": entry.get("url"),
            "matched_keywords": overlap[:10],
            "relevance": score,
        }
        for score, overlap, entry in scored[:limit]
    ]

    ev = candidate.evidence or {}
    ev["audit_knowledge"] = {
        "corpus_version": corpus.get("version", 0),
        "entry_count": corpus.get("entry_count", 0),
        "matches": matches,
        "note": (
            "Historical matches are precedent/context only; they do not prove "
            "this target is exploitable."
        ),
    }
    if not matches and candidate.impact_score >= 8:
        ev["audit_knowledge"]["no_close_match"] = True
        ev["audit_knowledge"]["note"] += " No close corpus match was found, so require concrete target-specific evidence."
    candidate.evidence = ev
    return matches


def _candidate_tokens(candidate: FindingCandidate) -> set[str]:
    ev = candidate.evidence or {}
    parts = [
        candidate.detector,
        candidate.title,
        candidate.description,
        " ".join(candidate.affected_functions or []),
        str(ev.get("bug_class", "")),
        str(ev.get("rule_id", "")),
        str(ev.get("function", "")),
    ]
    return _tokens(" ".join(parts))


def _tokens(text: str) -> set[str]:
    return {
        w
        for w in re.findall(r"[a-z][a-z0-9_]{3,}", (text or "").lower())
        if w not in _STOP and not w.isdigit()
    }
