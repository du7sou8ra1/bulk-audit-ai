"""Detectors: cross-chain receiver replay / domain-binding gaps (lead-level).

1. MessageReplayNoNonceDetector — an lzReceive/ccipReceive/handle receiver that moves
   funds and takes a guid/messageId/nonce, but never writes a processed-marker map
   (no `<idmap>[id] = true`, no `require(!processed[id])`). Replayable mint/credit.

2. RetryDomainBindingDetector — a retry/lzCompose/executeMessage that takes origin
   fields (srcEid/sender/nonce) as its OWN params and uses them for auth or a fund
   effect, with no onlyEndpoint gate and no `keccak256(...) == storedHash` reconciliation.

Both are lead/needs-poc: dedup/binding can live in an inherited base the single-file
probe can't see, so they key on "id/origin param present but never persisted/reconciled".
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_RECEIVER_RE = re.compile(r"^(_?lzReceive|_?ccipReceive|handle|_?nonblockingLzReceive|_?execute)$", re.I)
_ID_PARAM_RE = re.compile(r"\b(guid|messageId|msgId|nonce|_guid|deliveryHash|sequence)\b", re.I)
_FUND_EFFECT_RE = re.compile(r"(balanceOf|balances|_balances)\s*\[[^\]]*\]\s*\+=|_mint\s*\(|\.transfer\s*\(|safeTransfer", re.I)
_PROCESSED_MARKER_RE = re.compile(
    r"\w+\s*\[[^\]]*\]\s*=\s*(true|1)\b|require\s*\(\s*!\s*\w+\s*\[|"
    r"processed|executed|consumed|usedNonces?|isProcessed|_seen",
    re.I,
)

_RETRY_RE = re.compile(r"^(retry\w*|lzCompose|composeMsg|executeMessage|processRetry)$", re.I)
_ORIGIN_PARAM_RE = re.compile(r"\b(srcEid|srcChainId|sourceChainSelector|sender|origin|nonce)\b", re.I)
_ONLY_ENDPOINT_RE = re.compile(r"onlyEndpoint|onlyMailbox|onlyRouter|msg\.sender\s*==\s*(endpoint|mailbox|router)", re.I)
_HASH_RECONCILE_RE = re.compile(r"==\s*\w*[Hh]ash|keccak256\s*\([^;]*==|storedHash|expectedHash", re.I)
_AUTH_OR_FUND_RE = re.compile(r"require\s*\(|balances?\s*\[|_mint\s*\(|\.transfer\s*\(", re.I)


class MessageReplayNoNonceDetector(Detector):
    name = "message_replay_no_nonce"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, params, _t, raw_body in iter_function_bodies(source):
                if not _RECEIVER_RE.match(fname):
                    continue
                body = strip_comments(raw_body)
                if not _ID_PARAM_RE.search(params or "") and not _ID_PARAM_RE.search(body):
                    continue
                if not _FUND_EFFECT_RE.search(body):
                    continue
                if _PROCESSED_MARKER_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector="message_replay_no_nonce",
                    title=f"Cross-chain receiver moves funds with no replay marker: {fname}",
                    description=(
                        f"`{fname}` credits/mints funds and takes a message id/nonce but never records a "
                        "processed-marker (`processed[id] = true` / `require(!processed[id])`). If the same "
                        "message can be delivered twice, the mint/credit is replayable. Persist and check a "
                        "per-message consumed flag."
                    ),
                    impact_score=8.0,
                    confidence_score=4.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "bug_class": "message_replay_no_nonce", "needs_poc": True},
                    next_tests=[
                        "Deliver the same message id twice on a fork; expect the 2nd to revert",
                        "Confirm no processed/executed marker is set for the message id (incl. inherited bases)",
                    ],
                    affected_functions=[fname],
                ))
        return out


class RetryDomainBindingDetector(Detector):
    name = "retry_domain_binding"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, params, tail, raw_body in iter_function_bodies(source):
                if not _RETRY_RE.match(fname):
                    continue
                if not _ORIGIN_PARAM_RE.search(params or ""):
                    continue
                body = strip_comments(raw_body)
                if not _AUTH_OR_FUND_RE.search(body):
                    continue
                if _ONLY_ENDPOINT_RE.search(tail) or _ONLY_ENDPOINT_RE.search(body):
                    continue
                if _HASH_RECONCILE_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector="retry_domain_binding",
                    title=f"Retry/compose trusts caller-supplied origin without reconciliation: {fname}",
                    description=(
                        f"`{fname}` takes origin fields (srcEid/sender/nonce) as its OWN parameters and uses "
                        "them for auth or a fund effect, but is not gated by onlyEndpoint and never reconciles "
                        "them against state hashed at receive time (`keccak256(origin) == storedHash`). An "
                        "attacker can forge the origin to replay or spoof a cross-chain message."
                    ),
                    impact_score=8.0,
                    confidence_score=4.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "bug_class": "retry_domain_binding", "needs_poc": True},
                    next_tests=[
                        "Call the retry/compose fn directly with forged origin params on a fork",
                        "Confirm no onlyEndpoint gate and no ==storedHash reconciliation",
                    ],
                    affected_functions=[fname],
                ))
        return out
