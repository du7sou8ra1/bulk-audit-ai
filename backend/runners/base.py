"""Shared types + helpers for external-tool runners."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.command_runner import CommandResult, which


@dataclass
class RunnerResult:
    tool_name: str
    status: str  # ok | failed | timeout | skipped
    command: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    stdout_path: str | None = None
    stderr_path: str | None = None
    json_output_path: str | None = None
    summary: str = ""
    # Normalized findings: {"check","impact","confidence","description","location"}
    findings: list[dict] = field(default_factory=list)
    # Tool-specific structured data (e.g. forge: tests_run / tests_passed).
    meta: dict = field(default_factory=dict)

    @classmethod
    def skipped(cls, tool: str, reason: str) -> "RunnerResult":
        return cls(tool_name=tool, status="skipped", summary=reason)

    @classmethod
    def from_command(cls, tool: str, cmd: CommandResult) -> "RunnerResult":
        status = "ok"
        if cmd.timed_out:
            status = "timeout"
        elif not cmd.found:
            status = "skipped"
        elif cmd.exit_code not in (0, None):
            status = "failed"
        return cls(
            tool_name=tool,
            status=status,
            command=cmd.command,
            exit_code=cmd.exit_code,
            timed_out=cmd.timed_out,
            stdout_path=cmd.stdout_path,
            stderr_path=cmd.stderr_path,
        )


def tool_available(executable: str) -> bool:
    return which(executable) is not None
