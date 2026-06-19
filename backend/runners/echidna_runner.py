"""Echidna runner STUB (optional, v0.2).

Echidna requires a separate (non-pip) install and a properties harness, so it
is disabled in the MVP. The runner only reports availability for Tool Health.
  TODO: generate property tests for invariants surfaced by detectors
  TODO: run `echidna <contract> --config <yaml>` against a local fork
"""
from __future__ import annotations

from ..core.command_runner import which
from .base import RunnerResult


def echidna_available() -> bool:
    return which("echidna") is not None or which("echidna-test") is not None


def run_echidna(*args, **kwargs) -> RunnerResult:
    return RunnerResult.skipped("echidna", "echidna integration deferred to v0.2")
