"""Detector: authorized claim with no consumed-marker (helper-delegated verification).

A non-view external claim/redeem that verifies eligibility via a Merkle proof / signature
— even through a helper like `_verify(proof, leaf)` — and moves value, but sets/reads NO
consumed marker (claimed[]/nullifier/nonce/bitmap), is replayable: the same proof drains
the contract repeatedly. The existing whitelist/merkle detectors require the proof keyword
INSIDE the claim body, so they miss the helper-delegated shape.

FP mitigation (very-high EV, medium FP): fire only when the fn moves value, calls a
verify/proof helper, the contract has a merkleRoot/signer, and NO consumed-marker token
appears anywhere reachable.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_CLAIM_FN_RE = re.compile(r"^(claim|redeem|withdraw|collect|mint)\w*$", re.I)
_VERIFY_HELPER_RE = re.compile(r"\b\w*[Vv]erify\w*\s*\(|\bcheckProof\s*\(|\b_?verifyProof\s*\(|MerkleProof\s*\.\s*verify", )
_ROOT_SIGNER_RE = re.compile(r"merkleRoot|\bmerkle\b|\broot\b|\bsigner\b|whitelistSigner", re.I)
_VALUE_MOVE_RE = re.compile(r"\.transfer\s*\(|safeTransfer\s*\(|_mint\s*\(|\.call\s*\{\s*value", re.I)
_CONSUMED_MARKER_RE = re.compile(
    r"claimed|hasClaimed|isClaimed|nullifier|_setClaimed|used\s*\[|usedNonces?|nonce\s*\[|"
    r"bitmap|consumed|spent\s*\[|processed",
    re.I,
)
_EXTERNAL_RE = re.compile(r"\b(external|public)\b")
_VIEW_RE = re.compile(r"\b(view|pure)\b")


class ClaimReplayNoMarkerDetector(Detector):
    name = "claim_replay_no_marker"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _ROOT_SIGNER_RE.search(source):
                continue
            for fname, _p, tail, raw_body in iter_function_bodies(source):
                if not _CLAIM_FN_RE.match(fname):
                    continue
                if not _EXTERNAL_RE.search(tail) or _VIEW_RE.search(tail):
                    continue
                body = strip_comments(raw_body)
                if not (_VERIFY_HELPER_RE.search(body) and _VALUE_MOVE_RE.search(body)):
                    continue
                # A consumed marker anywhere reachable (body) means it is not replayable.
                if _CONSUMED_MARKER_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector="claim_replay_no_marker",
                    title=f"Authorized claim has no consumed-marker (replayable): {fname}",
                    description=(
                        f"`{fname}` verifies eligibility (via a Merkle proof / signature helper) and moves value "
                        "but never records a consumed marker (claimed[]/nullifier/nonce). The same proof or "
                        "signature can be replayed to drain the contract repeatedly. Mark the leaf/nullifier "
                        "consumed before paying out."
                    ),
                    impact_score=8.5,
                    confidence_score=4.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "bug_class": "claim_replay_no_marker", "needs_poc": True},
                    next_tests=[
                        "Call the claim twice with the same proof/signature on a fork; expect the 2nd to revert",
                        "Confirm no claimed/nullifier/nonce marker is set (incl. modifiers / inherited bases)",
                    ],
                    affected_functions=[fname],
                ))
        return out
