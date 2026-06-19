"""Detector STUB: privacy-pool / mixer invariants (v0.2).

Planned logic (per spec):
  TODO: nullifier marked spent BEFORE vs AFTER external transfer
  TODO: known-root check present
  TODO: proof binds root / nullifier / recipient / relayer / fee
  TODO: fee <= denomination
  TODO: external transfer must occur AFTER state update (CEI)
Flag if nullifier is marked after external transfer, root unchecked, or
recipient not a public input / proof-bound.
"""
from __future__ import annotations

from .base import Detector, FindingCandidate, TargetContext


class PrivacyPoolDetector(Detector):
    name = "privacy_pool"
    profiles = None  # primarily for the "privacy-pool-focused" profile in v0.2

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        return []
