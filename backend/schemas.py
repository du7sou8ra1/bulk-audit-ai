"""Pydantic schemas for the API layer (request bodies + response models)."""
from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #
# Valid profiles come straight from the detector registry (single source of
# truth) so the API and the registry can never disagree.
try:
    from .detectors.registry import PROFILE_NAMES as SCAN_PROFILES
except Exception:  # pragma: no cover - defensive fallback
    SCAN_PROFILES = ["deep"]


class ScanToggles(BaseModel):
    slither: bool | None = None
    mythril: bool | None = None
    semgrep: bool | None = None
    foundry: bool | None = None
    fuzzing: bool | None = None
    bytecode_intel: bool | None = None
    bytecode_probes: bool | None = None
    deepseek: bool | None = None
    invariant_reasoner: bool | None = None
    refutation: bool | None = None
    flashloan_sim: bool | None = None
    value_context: bool | None = None
    sanity_liveness: bool | None = None
    refuter_precision_rules: bool | None = None
    binding_hard_gate: bool | None = None
    critical_value_gate: bool | None = None
    pattern_priors: bool | None = None
    aderyn: bool | None = None
    analyzer_findings: bool | None = None
    chain_liveness: bool | None = None


class TargetInput(BaseModel):
    address: str
    label: str = ""


class CreateScanRequest(BaseModel):
    name: str = ""
    chain: str = "ethereum"
    scan_profile: str = "deep"
    # Either a list of structured targets or a raw blob of pasted addresses.
    targets: list[TargetInput] = Field(default_factory=list)
    addresses_blob: str = ""
    toggles: ScanToggles = Field(default_factory=ScanToggles)
    companion_expansion: bool = False
    companion_expansion_max: int = Field(default=8, ge=0, le=25)

    @field_validator("scan_profile")
    @classmethod
    def _coerce_profile(cls, v: str) -> str:
        # Single-mode build: there is one profile, "deep" (runs every detector).
        # Coerce any legacy/stale client value to it instead of returning a 422,
        # so the tool always runs the full set no matter what the client sends.
        return v if v in SCAN_PROFILES else "deep"


class FindingStatusUpdate(BaseModel):
    status: str  # open | false_positive | needs_more_investigation | confirmed


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #
class ToolRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    tool_name: str
    status: str
    started_at: dt.datetime | None = None
    finished_at: dt.datetime | None = None
    command: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    summary: str | None = None


class AIReviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    model: str
    classification: str | None = None
    rationale: str | None = None
    recommended_next_steps: list[Any] = Field(default_factory=list)
    request_json: dict = Field(default_factory=dict)
    response_json: dict = Field(default_factory=dict)
    created_at: dt.datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    detector: str
    title: str
    severity_candidate: str
    confidence_before_ai: str
    impact_score: float
    confidence_score: float
    status: str
    classification: str
    description: str
    evidence_json: dict = Field(default_factory=dict)
    next_tests_json: list[Any] = Field(default_factory=list)
    created_at: dt.datetime


class FindingDetailOut(FindingOut):
    ai_review: AIReviewOut | None = None
    target_address: str = ""


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    address: str
    chain: str
    label: str
    status: str
    source_verified: bool
    contract_name: str | None = None
    is_proxy: bool
    proxy_type: str | None = None
    implementation_address: str | None = None
    proxy_admin: str | None = None
    owner: str | None = None
    balance_eth: float | None = None
    error: str | None = None
    updated_at: dt.datetime


class TargetDetailOut(TargetOut):
    tool_runs: list[ToolRunOut] = Field(default_factory=list)
    findings: list[FindingOut] = Field(default_factory=list)
    protocol_graph: dict = Field(default_factory=dict)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    created_at: dt.datetime
    started_at: dt.datetime | None = None
    finished_at: dt.datetime | None = None
    status: str
    chain: str
    scan_profile: str
    toggles: dict = Field(default_factory=dict)
    total_targets: int
    completed_targets: int
    critical_count: int
    needs_investigation_count: int
    low_info_count: int
    false_positive_count: int
    error: str | None = None


class ScanDetailOut(ScanOut):
    targets: list[TargetOut] = Field(default_factory=list)
    protocol_graph: dict = Field(default_factory=dict)


class DashboardStats(BaseModel):
    total_scans: int
    running_scans: int
    completed_scans: int
    critical_candidates: int
    needs_investigation: int
    low_info: int
    false_positives: int
    recent_scans: list[ScanOut] = Field(default_factory=list)


class ToolHealthItem(BaseModel):
    name: str
    installed: bool
    version: str | None = None
    path: str | None = None
    warning: str | None = None


class ToolHealthOut(BaseModel):
    checked_at: dt.datetime
    tools: list[ToolHealthItem]
