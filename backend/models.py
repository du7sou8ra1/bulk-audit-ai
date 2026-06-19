"""SQLAlchemy ORM models for BulkAuditAI.

Five tables map directly to the spec: Scan, Target, ToolRun, Finding, AIReview.
Raw tool output, evidence and AI payloads are stored on disk (paths recorded
here) so the DB stays small and human-auditable.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- #
# Status / classification constants (kept as plain strings for SQLite ease).
# --------------------------------------------------------------------------- #
class ScanStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TargetStatus:
    QUEUED = "queued"
    FETCHING = "fetching"
    RESOLVING = "resolving"
    DETECTING = "detecting"
    TOOLS = "running_tools"
    AI = "ai_review"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ToolStatus:
    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class Classification:
    CONFIRMED_CRITICAL = "CONFIRMED_CRITICAL"
    LIKELY_CRITICAL_NEEDS_POC = "LIKELY_CRITICAL_NEEDS_POC"
    NEEDS_MORE_INVESTIGATION = "NEEDS_MORE_INVESTIGATION"
    LOW_OR_INFO = "LOW_OR_INFO"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    ALL = [
        CONFIRMED_CRITICAL,
        LIKELY_CRITICAL_NEEDS_POC,
        NEEDS_MORE_INVESTIGATION,
        LOW_OR_INFO,
        FALSE_POSITIVE,
    ]


# --------------------------------------------------------------------------- #
class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.QUEUED)

    chain: Mapped[str] = mapped_column(String(32), default="ethereum")
    rpc_url_name: Mapped[str] = mapped_column(String(255), default="")
    scan_profile: Mapped[str] = mapped_column(String(32), default="standard")
    # Per-scan tool/AI toggles (JSON) overriding env defaults.
    toggles: Mapped[dict] = mapped_column(JSON, default=dict)

    total_targets: Mapped[int] = mapped_column(Integer, default=0)
    completed_targets: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    needs_investigation_count: Mapped[int] = mapped_column(Integer, default=0)
    low_info_count: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    targets: Mapped[list["Target"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    address: Mapped[str] = mapped_column(String(42), index=True)
    chain: Mapped[str] = mapped_column(String(32), default="ethereum")
    label: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default=TargetStatus.QUEUED)

    source_verified: Mapped[bool] = mapped_column(default=False)
    contract_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_proxy: Mapped[bool] = mapped_column(default=False)
    proxy_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    implementation_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    proxy_admin: Mapped[str | None] = mapped_column(String(42), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(42), nullable=True)
    balance_eth: Mapped[float | None] = mapped_column(Float, nullable=True)

    workspace_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    scan: Mapped["Scan"] = relationship(back_populates="targets")
    tool_runs: Mapped[list["ToolRun"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    tool_name: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default=ToolStatus.PENDING)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timed_out: Mapped[bool] = mapped_column(default=False)
    stdout_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    json_output_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="tool_runs")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    detector: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512))
    severity_candidate: Mapped[str] = mapped_column(String(32), default="info")
    confidence_before_ai: Mapped[str] = mapped_column(String(32), default="low")
    impact_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    # User-controllable triage status (open / false_positive / needs_more / confirmed).
    status: Mapped[str] = mapped_column(String(32), default="open")
    # AI (or pre-AI) classification, one of Classification.ALL.
    classification: Mapped[str] = mapped_column(
        String(48), default=Classification.NEEDS_MORE_INVESTIGATION
    )
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    next_tests_json: Mapped[list] = mapped_column(JSON, default=list)
    # Plain column (no DB-level FK) to avoid a circular FK with ai_reviews.
    # The link is managed/queried manually; AIReview.finding_id is the canonical FK.
    ai_review_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    target: Mapped["Target"] = relationship(back_populates="findings")


class AIReview(Base):
    __tablename__ = "ai_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    model: Mapped[str] = mapped_column(String(64), default="")
    prompt_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_json: Mapped[dict] = mapped_column(JSON, default=dict)
    response_json: Mapped[dict] = mapped_column(JSON, default=dict)
    classification: Mapped[str | None] = mapped_column(String(48), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_next_steps: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
