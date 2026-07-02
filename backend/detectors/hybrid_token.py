"""Detector: ERC-404 / DN-404 hybrid-ledger desync on transfer.

Hybrid tokens keep TWO ledgers — an ERC20 balance map and an ERC721 ownership map —
that must stay in sync: an ERC20 transfer that crosses a whole-`unit` boundary must
mint/burn the paired NFT. A balance-mutating transfer that updates ERC20 balances but
never touches the NFT ledger (no `_mintERC721`/`_burnERC721`/rebalance) and never
recomputes the `/unit` threshold desyncs the two — minting free NFTs or double-spending
fractional value, draining the NFT floor. (2024 ERC404/DN404 fork wave.)

Hard co-occurrence marker gate (ERC20 map AND ERC721 map AND a unit constant) excludes
essentially all pure-ERC20 / pure-ERC721 code, keeping FP low.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_ERC20_LEDGER_RE = re.compile(r"\bbalanceOf\b|\b_balances\b")
_ERC721_LEDGER_RE = re.compile(r"\b_ownerOf\b|\b_owned\b|\b_ownedIndex\b|\bgetApproved\b|ownerOf\s*\(")
_UNIT_RE = re.compile(r"\bunit\b|unitsPerToken|\b_UNIT\b|\bunits\b|_WAD\b", re.IGNORECASE)
_HYBRID_HINT_RE = re.compile(r"erc404|dn404|\b_owned\b|mirrorERC721|skipNFT", re.IGNORECASE)
_NFT_SYNC_RE = re.compile(
    r"_mintERC721|_burnERC721|_transferERC721|_retrieveOrMint|rebalance|_setOwned|"
    r"_pushOwned|_popOwned|_withdrawAndBurn|_ownerOf\s*\[",
    re.IGNORECASE,
)
_UNIT_RECOMPUTE_RE = re.compile(r"/\s*_?unit|>>\s*|/\s*units|/\s*_UNIT", re.IGNORECASE)
_BAL_MUTATE_RE = re.compile(r"(balanceOf|_balances)\s*\[[^\]]*\]\s*[-+]?=|_transferERC20")
_TRANSFER_NAME_RE = re.compile(r"^(_?transfer|transferFrom|_transferERC20|_update)$", re.I)


class Erc404LedgerDesyncDetector(Detector):
    name = "erc404_ledger_desync"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            text = source
            # Hard marker gate: must look like a hybrid token.
            has_erc20 = bool(_ERC20_LEDGER_RE.search(text))
            has_erc721 = bool(_ERC721_LEDGER_RE.search(text))
            has_unit = bool(_UNIT_RE.search(text))
            hint = bool(_HYBRID_HINT_RE.search(text))
            if not (has_erc20 and has_erc721 and (has_unit or hint)):
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if not _TRANSFER_NAME_RE.match(fname):
                    continue
                body = strip_comments(raw_body)
                if not _BAL_MUTATE_RE.search(body):
                    continue  # this fn does not actually move ERC20 balances
                if _NFT_SYNC_RE.search(body) or _UNIT_RECOMPUTE_RE.search(body):
                    continue  # it does sync the NFT ledger / recompute the threshold
                out.append(FindingCandidate(
                    detector="erc404_ledger_desync",
                    title=f"Hybrid ERC-404/DN-404 transfer moves ERC20 balance without NFT resync: {fname}",
                    description=(
                        f"`{fname}` mutates the ERC20 balance ledger but never calls the paired NFT "
                        "mint/burn/rebalance helper and never recomputes the `/unit` NFT threshold. In an "
                        "ERC-404/DN-404 hybrid the two ledgers must stay in sync — a transfer that crosses a "
                        "whole-unit boundary must mint/burn the mirror NFT. Skipping it desyncs the ledgers, "
                        "minting free NFTs or double-spending fractional value and draining the NFT floor."
                    ),
                    impact_score=8.0,
                    confidence_score=5.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={
                        "function": fname, "file": path, "bug_class": "erc404_ledger_desync",
                        "needs_poc": True,
                    },
                    next_tests=[
                        "Transfer across a whole-unit boundary on a fork; check NFT balance vs ERC20 balance stay consistent",
                        "Confirm no _mintERC721/_burnERC721/rebalance runs on this path",
                    ],
                    affected_functions=[fname],
                ))
        return out
