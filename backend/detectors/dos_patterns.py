"""Detector: push-payment DoS on a critical path (King-of-Ether class, lead-level).

On a settlement/refund path (bid/refund/settle/distribute/auction), pushing ETH to a
previous actor's stored address (`highestBidder.transfer(...)`) means that actor can
revert on receive and permanently block the path — no one can outbid / settle. The safe
pattern credits a mapping and lets recipients pull.

Gated on: a critical-path fn name + a push send to a *previous-actor* storage address
(highestBidder/prevBidder/winner/beneficiary...) + no pull-credit mapping in the body.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_CRITICAL_FN_RE = re.compile(r"^(bid|refund|settle|distribute|auction\w*|finalize|claim|payout|close\w*)$", re.I)
_PREV_ACTOR_RE = re.compile(
    r"(highestBidder|previousBidder|prevBidder|lastBidder|currentWinner|winner|beneficiary|recipient|prevOwner|lastOwner)",
    re.I,
)
_PUSH_SEND_RE = re.compile(
    r"(?:payable\s*\(\s*)?(highestBidder|previousBidder|prevBidder|lastBidder|currentWinner|winner|beneficiary|recipient|prevOwner|lastOwner)"
    r"\s*\)?\s*\.\s*(transfer|send)\s*\(|"
    r"\b(highestBidder|previousBidder|prevBidder|lastBidder|currentWinner|winner|beneficiary|recipient)\b[^;]*\.call\s*\{\s*value",
    re.I,
)
_PULL_PATTERN_RE = re.compile(r"pending\w*\s*\[|credits?\s*\[|claimable\s*\[|withdraw\w*\s*\[|balances?\s*\[[^\]]*\]\s*\+=", re.I)


class PushPaymentDosDetector(Detector):
    name = "push_payment_dos"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _PREV_ACTOR_RE.search(source):
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if not _CRITICAL_FN_RE.match(fname):
                    continue
                body = strip_comments(raw_body)
                if not _PUSH_SEND_RE.search(body):
                    continue
                if _PULL_PATTERN_RE.search(body):
                    continue  # uses a pull-credit pattern -> safe
                out.append(FindingCandidate(
                    detector="push_payment_dos",
                    title=f"Push payment to a previous actor blocks the critical path: {fname}",
                    description=(
                        f"`{fname}` pushes ETH to a stored previous-actor address (e.g. the prior bidder) on a "
                        "settlement path. That address can revert on receive and permanently brick the function "
                        "(no one can outbid/settle) — a griefing/DoS. Credit a `pending[recipient]` mapping and "
                        "let recipients withdraw (pull payments) instead of pushing."
                    ),
                    impact_score=7.0,
                    confidence_score=4.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "bug_class": "push_payment_dos", "needs_poc": True},
                    next_tests=[
                        "Register a reverting-receive contract as the previous actor, then trigger the path; expect a permanent revert",
                        "Confirm there is no pull-credit fallback for the pushed payment",
                    ],
                    affected_functions=[fname],
                ))
        return out
