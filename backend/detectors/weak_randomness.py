"""Detector: weak on-chain randomness (predictable PRNG).

Block-derived values are validator-influenceable and visible in the mempool, so
using them as randomness lets an attacker predict or grind the outcome — draining a
lottery/raffle, minting the rare NFT, or picking themselves as the winner.

Signal:
  * STRONG sources (almost only ever used as entropy): block.prevrandao,
    block.difficulty, blockhash(...), block.coinbase  -> fire directly.
  * WEAK/ambiguous sources (block.timestamp, block.number, gasleft) -> fire ONLY
    when hashed (keccak256/sha256) or reduced with `%`, i.e. actually used as
    entropy rather than as a plain deadline/height. This keeps deadline checks
    (`require(block.timestamp <= deadline)`) silent.

Calibrated as a lead (impact 7 / confidence 4.5 -> NEEDS_MORE_INVESTIGATION).
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_STRONG_RE = re.compile(r"block\.prevrandao|block\.difficulty|blockhash\s*\(|block\.coinbase")
_WEAK_RE = re.compile(r"block\.timestamp|block\.number|gasleft\s*\(")
_ENTROPY_USE_RE = re.compile(r"keccak256\s*\(|sha256\s*\(|%\s*[\w(]")


class WeakRandomnessDetector(Detector):
    name = "weak_randomness"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or "block." not in source and "blockhash" not in source and "gasleft" not in source:
                continue
            for fname, _params, _tail, raw_body in iter_function_bodies(source):
                body = strip_comments(raw_body)
                strong = bool(_STRONG_RE.search(body))
                weak_as_entropy = bool(_WEAK_RE.search(body) and _ENTROPY_USE_RE.search(body))
                if not (strong or weak_as_entropy):
                    continue
                src_kind = "block.prevrandao/difficulty/blockhash/coinbase" if strong else "block.timestamp/number/gasleft (hashed or mod-reduced)"
                out.append(FindingCandidate(
                    detector="weak_randomness",
                    title=f"Weak on-chain randomness from block data: {fname}",
                    description=(
                        f"`{fname}` derives randomness from {src_kind}. These values are "
                        "validator-influenceable and mempool-visible, so an attacker can predict or grind "
                        "the result (winner selection, NFT rarity, reward draw). Use a commit-reveal scheme "
                        "or a VRF (e.g. Chainlink VRF) instead of block data."
                    ),
                    impact_score=7.0,
                    confidence_score=4.5,
                    severity_candidate="high",
                    evidence={
                        "function": fname, "file": path, "bug_class": "weak_randomness",
                        "strong_source": strong, "snippet": raw_body[:1200], "needs_poc": True,
                    },
                    next_tests=[
                        "Precompute the block-derived value and confirm the outcome is predictable/grindable",
                        "Confirm the randomness selects a valuable outcome (winner, rare mint, reward)",
                    ],
                    affected_functions=[fname],
                ))
        return out
