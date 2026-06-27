"""Tool Health preflight: detect installed security tools, versions and paths.

A missing tool is reported (not fatal): scans still run and record a SKIPPED
ToolRun for anything unavailable.
"""
from __future__ import annotations

import datetime as dt

from .command_runner import run_command, which

# (display_name, [executable candidates], [arg-sets to try for a version])
_TOOLS: list[tuple[str, list[str], list[list[str]]]] = [
    ("slither", ["slither"], [["slither", "--version"]]),
    ("mythril", ["myth", "mythril"], [["myth", "version"], ["myth", "--version"]]),
    ("semgrep", ["semgrep"], [["semgrep", "--version"]]),
    ("forge", ["forge"], [["forge", "--version"]]),
    ("cast", ["cast"], [["cast", "--version"]]),
    ("anvil", ["anvil"], [["anvil", "--version"]]),
    ("solc-select", ["solc-select"], [["solc-select", "versions"]]),
    ("solc", ["solc"], [["solc", "--version"]]),
    ("python", ["python", "python3"], [["python", "--version"], ["python3", "--version"]]),
    ("node", ["node"], [["node", "--version"]]),
    ("echidna", ["echidna", "echidna-test"], [["echidna", "--version"], ["echidna-test", "--version"]]),
    ("medusa", ["medusa"], [["medusa", "--version"]]),
    ("halmos", ["halmos"], [["halmos", "--version"]]),
]

# Tools that are core vs optional (affects the warning text).
_OPTIONAL = {"anvil", "solc", "echidna", "medusa", "halmos"}


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return (text or "").strip()


def check_tools() -> dict:
    items: list[dict] = []
    for name, candidates, version_cmds in _TOOLS:
        path = None
        for c in candidates:
            path = which(c)
            if path:
                break

        installed = path is not None
        version = None
        warning = None

        if installed:
            failures: list[str] = []
            for cmd in version_cmds:
                if which(cmd[0]) is None:
                    continue
                res = run_command(cmd, timeout=25)
                out = (res.stdout or "").strip() or (res.stderr or "").strip()
                if out and res.ok:
                    version = _first_line(out)[:200]
                    break
                if res.timed_out:
                    failures.append(f"{cmd[0]} version check timed out")
                elif res.exit_code not in (None, 0):
                    detail = _first_line(out) or f"exit code {res.exit_code}"
                    failures.append(f"{cmd[0]} failed: {detail[:140]}")
            if version is None:
                installed = False
                warning = (
                    f"installed but unusable — {failures[0]}"
                    if failures
                    else "installed but version check produced no output"
                )
        else:
            if name in _OPTIONAL:
                warning = "optional tool not installed"
            else:
                warning = "not installed — related scans will be skipped"

        items.append(
            {
                "name": name,
                "installed": installed,
                "version": version,
                "path": path,
                "warning": warning,
            }
        )

    return {
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "tools": items,
    }
