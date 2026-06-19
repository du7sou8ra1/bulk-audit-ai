"""Detector STUB: token logic (mint/burn/transfer) abuse (v0.2).

Planned logic:
  TODO: flag mint()/burn() without onlyOwner/onlyRole near the declaration
  TODO: detect unchecked transfer/transferFrom return values
  TODO: detect fee-on-transfer / rebasing accounting mismatches
  TODO: detect balance/supply invariants broken by external hooks (ERC777/ERC1363)
"""
from __future__ import annotations

from .base import Detector, FindingCandidate, TargetContext


class TokenLogicDetector(Detector):
    name = "token_logic"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        return []
