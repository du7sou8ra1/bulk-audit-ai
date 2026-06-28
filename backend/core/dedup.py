"""Dedup + false-positive learning (bulk-scale precision).

A bulk scanner over hundreds of contracts re-flags the same shapes endlessly.
This gives every finding a stable FINGERPRINT (detector + function + normalized
title + file) so:

  * the user can mark one a false-positive and have every future match auto-
    suppressed (global, or scoped to one address),
  * the pipeline can skip the expensive refute/PoC/AI steps on a known FP.

Normalization strips addresses/numbers so cosmetic differences don't change the
fingerprint.
"""
from __future__ import annotations

import hashlib
import re

from sqlalchemy import select

from ..config import get_settings
from ..database import SessionLocal
from ..detectors.base import FindingCandidate
from ..models import SuppressedFinding

_WS = re.compile(r"\s+")
_HEX = re.compile(r"0x[0-9a-fA-F]{4,}")
_NUM = re.compile(r"\b\d+\b")
_PATTERN_PREFIX = "pat:"
_PATTERN_MARKERS = (
    "transferFrom(msg.sender",
    "safeTransferFrom(msg.sender",
    "require(msg.sender==address(this))",
    "require(msg.sender == address(this))",
    "factory==address(0)",
    "factory == address(0)",
    "slot0.sqrtPriceX96==0",
    "slot0.sqrtPriceX96 == 0",
    "onlyOwner",
    "onlyRole",
    "nonReentrant",
    "initializer",
    "reinitializer",
)


def _norm_title(title: str) -> str:
    t = (title or "").lower()
    t = _HEX.sub("0x", t)
    t = _NUM.sub("n", t)
    return _WS.sub(" ", t).strip()


def fingerprint(detector: str, title: str,
                affected_functions: list[str] | None = None, file: str = "") -> str:
    fn = (affected_functions or [""])[0] or ""
    base = f"{detector}|{fn}|{_norm_title(title)}|{(file or '').replace(chr(92), '/').split('/')[-1]}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()


def candidate_fingerprint(candidate: FindingCandidate) -> str:
    ev = candidate.evidence or {}
    return fingerprint(candidate.detector, candidate.title,
                       candidate.affected_functions, ev.get("file", ""))


def pattern_signature(candidate: FindingCandidate) -> str:
    """Address-free code-pattern key used as refuter context, not suppression."""
    ev = candidate.evidence or {}
    fn = ((candidate.affected_functions or [""])[0] or "").lstrip("_").lower()
    snippet = _WS.sub("", str(ev.get("snippet", "") or ""))
    markers = [m.lower().replace(" ", "") for m in _PATTERN_MARKERS if m.lower().replace(" ", "") in snippet.lower()]
    rule = str(ev.get("rule_id") or ev.get("bug_class") or _norm_title(candidate.title))
    pattern_class = str(ev.get("refutation_pattern_class") or ev.get("bug_class") or "")
    base = f"{candidate.detector}|{fn}|{rule}|{pattern_class}|{','.join(sorted(markers))}"
    return _PATTERN_PREFIX + hashlib.sha1(base.encode("utf-8")).hexdigest()[:40]


def _content_key(candidate: FindingCandidate) -> str:
    """Content fingerprint EXCLUDING the file path — so the SAME finding emitted
    from proxy + implementation + flattened copies collapses to one. A body hash
    keeps two genuinely different functions that share a name separate."""
    ev = candidate.evidence or {}
    fn = ((candidate.affected_functions or [""])[0] or "").lstrip("_").lower()
    rule = ev.get("rule_id") or _norm_title(candidate.title)
    snippet = _WS.sub("", str(ev.get("snippet", "") or ""))
    body_hash = hashlib.sha1(snippet.encode("utf-8")).hexdigest()[:12] if snippet else ""
    return f"{candidate.detector}|{fn}|{rule}|{body_hash}"


def collapse_duplicates(candidates: list[FindingCandidate]) -> list[FindingCandidate]:
    """Collapse cross-compilation-unit duplicates (same detector+function+rule+body
    from several source files) into ONE representative, recording the other files in
    evidence['also_in_files'] (never silently dropped) and a dup_count. Keeps the
    strongest impact/confidence. MUST run AFTER corroboration so it sees all copies.
    """
    seen: dict[str, FindingCandidate] = {}
    out: list[FindingCandidate] = []
    for c in candidates:
        key = _content_key(c)
        rep = seen.get(key)
        if rep is None:
            seen[key] = c
            out.append(c)
            continue
        ev = rep.evidence
        f = (c.evidence or {}).get("file")
        if f and f != ev.get("file"):
            also = ev.setdefault("also_in_files", [])
            if f not in also:
                also.append(f)
        ev["dup_count"] = int(ev.get("dup_count", 1)) + 1
        rep.impact_score = max(rep.impact_score, c.impact_score)
        rep.confidence_score = max(rep.confidence_score, c.confidence_score)
    return out


def is_suppressed(fp: str, address: str | None = None) -> tuple[bool, str]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(SuppressedFinding).where(SuppressedFinding.fingerprint == fp)
        ).all()
    for r in rows:
        if r.address is None or (address and r.address.lower() == address.lower()):
            return True, r.reason or "marked false-positive"
    return False, ""


def apply_suppression(candidate: FindingCandidate, address: str | None = None) -> bool:
    """Stamp the candidate with its fingerprint; flag + return True if suppressed."""
    fp = candidate_fingerprint(candidate)
    candidate.evidence["fingerprint"] = fp
    if get_settings().enable_pattern_priors:
        candidate.evidence["pattern_fingerprint"] = pattern_signature(candidate)
    suppressed, reason = is_suppressed(fp, address)
    if suppressed:
        candidate.evidence["suppressed"] = True
        candidate.evidence["suppressed_reason"] = reason
        return True
    if get_settings().enable_pattern_priors:
        prior, prior_reason = is_suppressed(candidate.evidence["pattern_fingerprint"], None)
        if prior:
            candidate.evidence.setdefault("prior_pattern_refutations", []).append(
                {
                    "pattern_fingerprint": candidate.evidence["pattern_fingerprint"],
                    "reason": prior_reason,
                    "note": "prior pattern context only; this does not auto-suppress the finding",
                }
            )
            candidate.evidence["prior_refutation_reason"] = prior_reason
    return False


def record_pattern_refutation(candidate: FindingCandidate, reason: str = "") -> str:
    """Store a concrete refutation as pattern wisdom, not an address denylist."""
    fp = pattern_signature(candidate)
    if not get_settings().enable_pattern_priors:
        return fp
    suppress(
        fp,
        address=None,
        detector=candidate.detector,
        title=f"pattern prior: {candidate.title}",
        reason=reason or str((candidate.evidence or {}).get("suppressed_reason") or "concrete pattern refutation"),
    )
    return fp


def suppress(fp: str, *, address: str | None = None, detector: str = "",
            title: str = "", reason: str = "user-marked false-positive") -> None:
    with SessionLocal() as db:
        # avoid duplicate suppression rows for the same (fp, address)
        existing = db.scalars(
            select(SuppressedFinding).where(SuppressedFinding.fingerprint == fp)
        ).all()
        for r in existing:
            if (r.address or None) == (address or None):
                return
        db.add(SuppressedFinding(fingerprint=fp, address=address, detector=detector,
                                 title=title[:500], reason=reason))
        db.commit()
