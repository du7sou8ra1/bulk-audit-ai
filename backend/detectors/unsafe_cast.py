"""Detector: unsafe narrowing downcast (silent truncation).

In Solidity >=0.8 arithmetic overflow reverts, but an EXPLICIT cast to a narrower
integer type does NOT — `uint128(x)` silently truncates when `x > type(uint128).max`.
When the truncated value is attacker-influenced and flows into accounting (a stored
balance / share / amount) or a value movement, an attacker can wrap a large value
down to a small one and corrupt the invariant (or funds are silently lost).

Low-FP gate: only a narrowing cast of a bare identifier (not a literal, not a
masked/bounded expression) with no visible `require(x <= type(uintN).max)` / bit-mask
guard in the same body. Calibrated as an investigation LEAD (never an auto-critical):
impact<=7, confidence<=4.5 -> classifies at NEEDS_MORE_INVESTIGATION, so it adds
signal without polluting the submit-ready/reportable set.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

# Narrowing integer widths (256 excluded).
_WIDTHS = "128|120|112|104|96|88|80|72|64|56|48|40|32|24|16|8"
_CAST_RE = re.compile(rf"\b(u?int(?:{_WIDTHS}))\s*\(\s*([A-Za-z_]\w*)\s*\)")
_STATE_OR_VALUE_RE = re.compile(
    r"\+=|-=|\bpush\s*\(|_mint\s*\(|_burn\s*\(|\.transfer\s*\(|safeTransfer|"
    r"\[[^\]]*\]\s*=|=\s*[^=]",
)


def _param_names(params: str) -> set[str]:
    names: set[str] = set()
    for part in (params or "").split(","):
        toks = part.strip().split()
        if len(toks) >= 2:
            names.add(toks[-1].strip())
    return names


class UnsafeDowncastDetector(Detector):
    name = "unsafe_downcast"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or "int" not in source:
                continue
            for fname, params, _tail, raw_body in iter_function_bodies(source):
                body = strip_comments(raw_body)
                pnames = _param_names(params)
                seen: set[str] = set()
                for m in _CAST_RE.finditer(body):
                    ttype, var = m.group(1), m.group(2)
                    if var in seen or var in ("max", "min") or var[0].isdigit():
                        continue
                    # Guarded: an explicit upper-bound check or a bit-mask on this var.
                    bounded = (
                        re.search(rf"require\s*\([^;]*\b{re.escape(var)}\b[^;]*(<=?|<)\s*(type\s*\(\s*{ttype}|2\s*\*\*|0x)", body)
                        or re.search(rf"\b{re.escape(var)}\b\s*&", body)
                        or re.search(rf"&[^;]*\b{re.escape(var)}\b", body)
                        or re.search(rf"\bSafeCast\b|\btoUint\d", body)
                    )
                    if bounded:
                        continue
                    seen.add(var)
                    from_param = var in pnames
                    feeds = bool(_STATE_OR_VALUE_RE.search(body))
                    impact = 7.0 if (from_param and feeds) else 5.0
                    conf = 4.5 if from_param else 3.5
                    tail_note = (
                        " It is a function parameter feeding a state write / value movement, so an "
                        "attacker can pass a value above the type max to truncate it."
                        if from_param and feeds else ""
                    )
                    out.append(FindingCandidate(
                        detector="unsafe_downcast",
                        title=f"Unsafe narrowing downcast to {ttype} may silently truncate: {fname}",
                        description=(
                            f"`{fname}` casts `{var}` to `{ttype}` explicitly. Solidity does not revert on a "
                            f"narrowing cast — if `{var}` exceeds type({ttype}).max it is silently truncated."
                            + tail_note
                            + f" Add require({var} <= type({ttype}).max) or use OZ SafeCast."
                        ),
                        impact_score=impact,
                        confidence_score=conf,
                        severity_candidate="high" if impact >= 7 else "medium",
                        evidence={
                            "function": fname, "file": path, "variable": var, "target_type": ttype,
                            "from_parameter": from_param, "feeds_state_or_value": feeds,
                            "bug_class": "unsafe_downcast", "snippet": raw_body[:1200], "needs_poc": True,
                        },
                        next_tests=[
                            f"Pass {var} > type({ttype}).max and confirm the stored/moved value truncates on a fork",
                            f"Confirm there is no bound check or SafeCast guarding {var}",
                        ],
                        affected_functions=[fname],
                    ))
        return out
