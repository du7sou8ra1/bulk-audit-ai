"""Detectors: DeFi call-site hygiene (value-literal signals the corpus rules miss).

1. SwapSlippageDeadlineDetector — a router/swap call where the min-out field is the
   literal 0, or the deadline field is `block.timestamp` / `type(uint256).max`. The
   existing corpus rule keys on the NAME of these params, so it self-suppresses when
   the param is present-but-zeroed; this keys on the dangerous VALUE.

2. MaxApproveMutableSpenderDetector — `approve/safeApprove(spender, type(uint256).max)`
   where `spender` is a state variable mutated by a setter (not immutable/constructor
   -only). A swapped/compromised strategy address then drains the whole allowance.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_SWAP_CTX_RE = re.compile(
    r"exactInput|exactOutput|swapExact|swapTokensFor|addLiquidity|removeLiquidity|"
    r"\brouter\b|IUniswap|ISwapRouter|IV3SwapRouter|PancakeRouter|\.swap\s*\(",
    re.IGNORECASE,
)
_MINOUT_ZERO_RE = re.compile(
    r"(amountOutMin(?:imum)?|minOut|minReceived|minReturn|minAmountOut|minShares|minAssets|minTokensOut)"
    r"\s*[:=]\s*0\b",
    re.IGNORECASE,
)
_DEADLINE_BAD_RE = re.compile(
    r"(deadline|expiry|validUntil)\s*[:=]\s*"
    r"(block\.timestamp|type\s*\(\s*uint256\s*\)\s*\.\s*max|~\s*uint256\s*\(\s*0\s*\))",
    re.IGNORECASE,
)

_MAX_UINT_RE = r"(?:type\s*\(\s*uint256\s*\)\s*\.\s*max|2\s*\*\*\s*256\s*-\s*1|~\s*uint256\s*\(\s*0\s*\)|uint256\s*\(\s*-\s*1\s*\))"
_APPROVE_MAX_RE = re.compile(
    r"(?:safeApprove|approve|forceApprove)\s*\(\s*([A-Za-z_]\w*)\s*,\s*" + _MAX_UINT_RE,
    re.IGNORECASE,
)
_SETTER_RE_TMPL = r"function\s+(?:set|update|change|configure|migrate)\w*[^{{]*\{{[^}}]*\b{var}\s*="


class SwapSlippageDeadlineDetector(Detector):
    name = "swap_missing_slippage_deadline"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _SWAP_CTX_RE.search(source):
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                body = strip_comments(raw_body)
                if not _SWAP_CTX_RE.search(body):
                    continue
                zero_minout = bool(_MINOUT_ZERO_RE.search(body))
                bad_deadline = bool(_DEADLINE_BAD_RE.search(body))
                if not (zero_minout or bad_deadline):
                    continue
                which = []
                if zero_minout:
                    which.append("a zero minimum-output (no slippage protection)")
                if bad_deadline:
                    which.append("a `block.timestamp`/max deadline (no deadline protection)")
                out.append(FindingCandidate(
                    detector="swap_missing_slippage_deadline",
                    title=f"Swap with no slippage/deadline protection: {fname}",
                    description=(
                        f"`{fname}` performs a router/AMM swap with " + " and ".join(which) + ". "
                        "This is sandwichable — a searcher can front/back-run the swap and extract the "
                        "difference. Pass a real minOut computed from an oracle/quote and a caller-supplied "
                        "deadline. (The value is literal here, so name-based checks do not catch it.)"
                    ),
                    impact_score=7.0,
                    confidence_score=5.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={
                        "function": fname, "file": path, "bug_class": "missing_slippage_deadline",
                        "zero_minout": zero_minout, "bad_deadline": bad_deadline, "needs_poc": True,
                    },
                    next_tests=[
                        "Simulate a sandwich around this swap on a fork; measure extractable value",
                        "Confirm minOut is 0 / deadline is block.timestamp at the live call site",
                    ],
                    affected_functions=[fname],
                ))
        return out


class MaxApproveMutableSpenderDetector(Detector):
    name = "max_approve_mutable_spender"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            clean = strip_comments(source)
            seen: set[str] = set()
            for m in _APPROVE_MAX_RE.finditer(clean):
                spender = m.group(1)
                if spender in seen or spender in ("address", "type"):
                    continue
                # Only a lead when the spender is a setter-mutable state var.
                setter = re.search(_SETTER_RE_TMPL.format(var=re.escape(spender)), clean, re.IGNORECASE | re.DOTALL)
                if not setter:
                    continue
                seen.add(spender)
                out.append(FindingCandidate(
                    detector="max_approve_mutable_spender",
                    title=f"Infinite approval to a setter-mutable spender: {spender}",
                    description=(
                        f"An unlimited (type(uint256).max) token approval is granted to `{spender}`, which is "
                        "reassigned by an admin setter rather than being immutable/constructor-only. If that "
                        "target is swapped to a malicious/compromised contract, the standing max allowance "
                        "lets it pull the full token balance in one call. Approve only the amount needed, or "
                        "reset to 0 before re-approving a new spender."
                    ),
                    impact_score=8.0,
                    confidence_score=5.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={
                        "file": path, "spender_var": spender, "bug_class": "max_approve_mutable_spender",
                        "needs_poc": True,
                    },
                    next_tests=[
                        f"Confirm `{spender}` is reassignable by an admin setter (not immutable)",
                        "Confirm the approval is type(uint256).max and never reset to 0",
                    ],
                    affected_functions=[],
                ))
        return out
