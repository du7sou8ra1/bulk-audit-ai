"""Robust external-command execution.

Every external tool (slither, myth, semgrep, forge, solc-select, ...) is run
through here so that:
  * there is always a hard timeout,
  * stdout/stderr are captured to files (never silently discarded),
  * exit code + timeout flag are recorded,
  * a failing tool never crashes the scan.

This module is intentionally synchronous; the async scanner calls it via
``asyncio.to_thread`` so several tools can run concurrently.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CommandResult:
    command: str
    args: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration: float
    found: bool = True  # whether the executable was found on PATH
    stdout_path: str | None = None
    stderr_path: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.found and not self.timed_out and self.exit_code == 0


def which(executable: str) -> str | None:
    """Resolve an executable on PATH (handles .exe/.cmd on Windows)."""
    return shutil.which(executable)


def run_command(
    args: list[str],
    *,
    timeout: int = 120,
    cwd: str | Path | None = None,
    output_dir: str | Path | None = None,
    output_prefix: str = "cmd",
    env: dict | None = None,
) -> CommandResult:
    """Run ``args`` with a timeout, capturing output to ``output_dir``.

    Never raises for tool failures — inspect the returned ``CommandResult``.
    """
    command_str = " ".join(args)
    exe = args[0]
    resolved = which(exe)
    if resolved is None:
        return CommandResult(
            command=command_str,
            args=args,
            exit_code=None,
            stdout="",
            stderr=f"executable not found on PATH: {exe}",
            timed_out=False,
            duration=0.0,
            found=False,
        )

    start = time.monotonic()
    timed_out = False
    stdout = ""
    stderr = ""
    exit_code: int | None = None

    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (
            (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        ) + f"\n[timeout after {timeout}s]"
    except Exception as exc:  # pragma: no cover - defensive
        stderr = f"[runner error] {type(exc).__name__}: {exc}"

    duration = time.monotonic() - start

    stdout_path = None
    stderr_path = None
    if output_dir is not None:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        sp = out_dir / f"{output_prefix}.stdout.txt"
        ep = out_dir / f"{output_prefix}.stderr.txt"
        sp.write_text(stdout, encoding="utf-8", errors="replace")
        ep.write_text(stderr, encoding="utf-8", errors="replace")
        stdout_path = str(sp)
        stderr_path = str(ep)

    return CommandResult(
        command=command_str,
        args=args,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        duration=duration,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def get_version(args: list[str], *, timeout: int = 20) -> CommandResult:
    """Lightweight wrapper for `<tool> --version`-style checks."""
    return run_command(args, timeout=timeout)
