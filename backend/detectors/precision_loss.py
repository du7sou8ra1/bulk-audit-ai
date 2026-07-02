"""Detector: divide-before-multiply precision loss.

Integer division truncates, so `a / b * c` loses precision that `a * c / b` would
keep. In share/reward/price math this rounds in an attacker-favorable direction or
zeroes a payout, and it underpins several rounding/first-depositor exploits. Slither
flags this as `divide-before-multiply`; this native detector covers the case where
Slither is not installed (and the finding is then promoted like any candidate).

Low-FP shape: a division whose quotient is directly multiplied in the SAME
sub-expression (`term / term ... * term`), with the denominator a bare term (not a
parenthesised `/ (b * c)`, which is safe) and excluding `**`. Calibrated as a lead:
value-context math -> NEEDS_MORE_INVESTIGATION; otherwise low/info.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

# term  /  denom(not '(')  ...same-precedence run...  * (single, not **)  term
_DIV_BEFORE_MUL_RE = re.compile(
    r"[\w.\)\]]\s*/\s*[\w.\[][\w.\(\)\[\]\s]*?\*(?!\*)\s*[\w.\(]"
)
_VALUE_CTX_RE = re.compile(
    r"reward|price|share|rate|amount|fee|mint|payout|assets?|debt|collateral|"
    r"interest|yield|weight|ratio|value|balance",
    re.IGNORECASE,
)


class DivideBeforeMultiplyDetector(Detector):
    name = "divide_before_multiply"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or "/" not in source:
                continue
            for fname, _params, _tail, raw_body in iter_function_bodies(source):
                body = strip_comments(raw_body)
                if not _DIV_BEFORE_MUL_RE.search(body):
                    continue
                value_ctx = bool(_VALUE_CTX_RE.search(fname) or _VALUE_CTX_RE.search(body))
                impact = 7.0 if value_ctx else 5.5
                out.append(FindingCandidate(
                    detector="divide_before_multiply",
                    title=f"Divide-before-multiply precision loss: {fname}",
                    description=(
                        f"`{fname}` divides then multiplies the quotient (`a / b * c`). Integer division "
                        "truncates first, losing precision that `a * c / b` would keep. In share/reward/"
                        "price accounting this rounds against users or zeroes small amounts and is a known "
                        "rounding-exploit primitive. Reorder to multiply before dividing, or use a mulDiv."
                    ),
                    impact_score=impact,
                    confidence_score=4.0,
                    severity_candidate="high" if impact >= 7 else "medium",
                    evidence={
                        "function": fname, "file": path, "bug_class": "divide_before_multiply",
                        "value_context": value_ctx, "snippet": raw_body[:1200], "needs_poc": True,
                    },
                    next_tests=[
                        "Compute the expression with a * c / b vs a / b * c on realistic inputs; confirm the delta",
                        "Confirm the rounding direction favors an attacker (share mint / reward / redemption)",
                    ],
                    affected_functions=[fname],
                ))
        return out
