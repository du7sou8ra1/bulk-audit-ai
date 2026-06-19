"""Detector STUB: ZK verifier misconfiguration (v0.2).

Planned logic (per spec):
  TODO: count public inputs vs verifier expectation
  TODO: verifier address mutability
  TODO: proof-accepting function name + public inputs reduced modulo field
  TODO: commitment hash construction
  TODO: Groth16 misconfig: gamma == delta, duplicated/zero verifying-key points
Findings here should always be CANDIDATE-only unless strong evidence exists.
"""
from __future__ import annotations

from .base import Detector, FindingCandidate, TargetContext


class ZkVerifierDetector(Detector):
    name = "zk_verifier"
    profiles = None  # primarily for the "zk-focused" profile in v0.2

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        return []
