"""Detector STUB: generalized access-control gap analysis (v0.2).

MVP access-control coverage lives inside ``proxy_upgrade``,
``governance_blast_radius`` and ``arbitrary_call`` (each checks for modifiers
near sensitive functions). This dedicated detector will add:
  TODO: build a per-function modifier graph (including inherited modifiers)
  TODO: detect state-changing functions with NO modifier and NO require(msg.sender==...)
  TODO: detect initializer() callable twice / missing initializer guard
  TODO: detect tx.origin authentication
"""
from __future__ import annotations

from .base import Detector, FindingCandidate, TargetContext


class AccessControlDetector(Detector):
    name = "access_control"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        return []
