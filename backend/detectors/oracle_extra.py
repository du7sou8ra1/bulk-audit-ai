"""Detector: TWAP window of zero / near-zero via constant-indirection.

A Uniswap-V3-style `observe()`/`consult()` whose `secondsAgo`/period resolves to 0 (or a
tiny value) is just a spot price wearing a TWAP costume — flash-loan manipulable. The
existing TWAP detector catches only the inline-literal shape; this resolves the common
`uint32 constant TWAP_INTERVAL = 0; secondsAgos[0] = TWAP_INTERVAL;` indirection.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, strip_comments

_TWAP_CTX_RE = re.compile(r"\.observe\s*\(|OracleLibrary|consult\s*\(|secondsAgo|\btwap\b|getQuoteAtTick", re.I)
_CONST_DECL_RE = re.compile(r"(?:uint\d*\s+)?(?:constant|immutable)\s+([A-Za-z_]\w*)\s*=\s*(\d+)\b")
# Only the FROM endpoint (secondsAgos[0]) being 0 means a zero window; secondsAgos[1]=0
# is the normal "to now" endpoint of a [window, 0] observe call.
_INLINE_ZERO_RE = re.compile(
    r"secondsAgos?\s*\[\s*0\s*\]\s*=\s*0\b|\bperiod\s*=\s*0\b|\btwapWindow\s*=\s*0\b|\bwindow\s*=\s*0\b|"
    r"\bsecondsAgo\s*=\s*0\b",
    re.I,
)


class TwapZeroWindowDetector(Detector):
    name = "twap_zero_window"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _TWAP_CTX_RE.search(source):
                continue
            text = strip_comments(source)
            reason = ""
            # (a) inline zero window
            if _INLINE_ZERO_RE.search(text):
                reason = "the TWAP window (secondsAgo/period) is set to 0 (spot price)"
            else:
                # (b) constant-indirection: a small constant used in a seconds/period/window context
                for m in _CONST_DECL_RE.finditer(text):
                    name, val = m.group(1), int(m.group(2))
                    if val > 60:
                        continue
                    if not re.search(r"(interval|period|window|twap|secondsAgo)", name, re.I):
                        # the constant name must look like a window, or be used in a window slot
                        if not re.search(r"secondsAgo\w*\s*(?:\[[^\]]*\])?\s*=\s*" + re.escape(name), text):
                            continue
                    reason = f"the TWAP window resolves to the constant `{name}` = {val} (spot / near-spot)"
                    break
            if not reason:
                continue
            out.append(FindingCandidate(
                detector="twap_zero_window",
                title="TWAP oracle window is zero / near-zero (spot-manipulable)",
                description=(
                    f"A TWAP price is read but " + reason + ". A zero or tiny averaging window makes the "
                    "'TWAP' a single-block spot price, which a flash loan can move within one transaction. "
                    "Use a real averaging window (e.g. 30 minutes) sized to the pool's liquidity."
                ),
                impact_score=7.0,
                confidence_score=4.5,  # NEEDS_MORE_INVESTIGATION lead
                severity_candidate="high",
                evidence={"file": path, "bug_class": "twap_zero_window", "needs_poc": True},
                next_tests=[
                    "Flash-loan-move the pool and read the TWAP in the same tx; confirm the price shifts",
                    "Confirm the observe/consult window argument resolves to 0 or a tiny constant",
                ],
                affected_functions=[],
            ))
        return out
