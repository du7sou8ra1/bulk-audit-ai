"""Detector STUB: dedicated delegatecall analysis (v0.2).

For the MVP, delegatecall is partly covered by ``arbitrary_call`` and the
Slither ``controlled-delegatecall`` signal. This dedicated detector will add:
  TODO: data-flow from msg.data / parameters into the delegatecall target
  TODO: storage-collision analysis between proxy and implementation layouts
  TODO: detect delegatecall in fallback() that forwards to a settable address
"""
from __future__ import annotations

from .base import Detector, FindingCandidate, TargetContext


class DelegatecallDetector(Detector):
    name = "delegatecall"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        # Intentionally no findings in v0.1 (see module docstring).
        return []
