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

from ..database import SessionLocal
from ..detectors.base import FindingCandidate
from ..models import SuppressedFinding

_WS = re.compile(r"\s+")
_HEX = re.compile(r"0x[0-9a-fA-F]{4,}")
_NUM = re.compile(r"\b\d+\b")


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
    suppressed, reason = is_suppressed(fp, address)
    if suppressed:
        candidate.evidence["suppressed"] = True
        candidate.evidence["suppressed_reason"] = reason
    return suppressed


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
