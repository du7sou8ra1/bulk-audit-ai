"""Detector: signed deadline never enforced (EIP-2612 permit / signed approval).

A signature-verifying function that SIGNS a `deadline`/`expiry`/`validUntil` (the field
appears inside the abi.encode/keccak digest) but never compares it to `block.timestamp`
turns any leaked/expired signed approval into a permanent bearer approval.

The existing signature_replay only checks whether the WORD `deadline` appears, so a
param literally named `deadline` makes it count the function as protected. This keys on
the missing block.timestamp comparison. Lead/needs-poc: the check can live in a modifier
or a one-hop helper, so it scans those before firing (residual FP -> not reportable).
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_SIG_RE = re.compile(r"\becrecover\s*\(|\.recover\s*\(|isValidSignature\s*\(|\\x19\\x01")
_DEADLINE_PARAM_RE = re.compile(r"\b(deadline|expiry|validUntil|validBefore|expiration)\b", re.I)
_SIGNED_RE = re.compile(r"abi\.encode\w*\s*\([^;]*\b(deadline|expiry|validUntil|expiration)\b", re.I)


def _timestamp_check_for(var: str, text: str) -> bool:
    # block.timestamp compared against the deadline identifier, either order.
    return bool(
        re.search(rf"block\.timestamp\s*(<=?|>=?)\s*[^;]*\b{re.escape(var)}\b", text)
        or re.search(rf"\b{re.escape(var)}\b\s*(<=?|>=?)\s*[^;]*block\.timestamp", text)
        or re.search(rf"require\s*\([^;]*\b{re.escape(var)}\b[^;]*block\.timestamp", text)
    )


class PermitMissingDeadlineDetector(Detector):
    name = "permit_missing_deadline"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _SIG_RE.search(source):
                continue
            # Modifiers / one-hop helpers may enforce it out-of-line -> scan whole file.
            whole = strip_comments(source)
            for fname, params, tail, raw_body in iter_function_bodies(source):
                body = strip_comments(raw_body)
                if not _SIG_RE.search(body):
                    continue
                m = _DEADLINE_PARAM_RE.search(params or "")
                if not m:
                    continue
                var = m.group(1)
                # Only if the deadline is actually SIGNED (bound into the digest).
                if not (_SIGNED_RE.search(body) or _SIGNED_RE.search(whole)):
                    continue
                # Enforced in the body, a modifier, or anywhere reachable in the file?
                if _timestamp_check_for(var, body) or _timestamp_check_for(var, tail) or _timestamp_check_for(var, whole):
                    continue
                out.append(FindingCandidate(
                    detector="permit_missing_deadline",
                    title=f"Signed deadline is never enforced: {fname}",
                    description=(
                        f"`{fname}` verifies a signature over a digest that binds `{var}` but never compares "
                        f"`{var}` against `block.timestamp`. The deadline is therefore cosmetic — a leaked or "
                        "'expired' signed approval remains valid forever (permanent bearer approval). Add "
                        f"`require(block.timestamp <= {var})`."
                    ),
                    impact_score=7.0,
                    confidence_score=3.5,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "deadline_var": var,
                              "bug_class": "permit_missing_deadline", "needs_poc": True},
                    next_tests=[
                        f"Submit a signed message with a past `{var}` on a fork; expect it to still succeed",
                        f"Confirm no block.timestamp comparison against `{var}` in the fn, its modifiers, or helpers",
                    ],
                    affected_functions=[fname],
                ))
        return out
