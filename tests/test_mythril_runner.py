"""Regression tests for the Mythril runner fast-pass guardrails."""
from pathlib import Path

from backend.core.command_runner import CommandResult
from backend.runners import mythril_runner


def _cmd(args: list[str], stdout: str, *, timed_out: bool = False) -> CommandResult:
    return CommandResult(
        command=" ".join(args),
        args=args,
        exit_code=None if timed_out else 0,
        stdout=stdout,
        stderr="",
        timed_out=timed_out,
        duration=0.01,
    )


def test_mythril_caps_requested_timeout(monkeypatch, tmp_path: Path):
    calls: list[tuple[list[str], int]] = []

    def fake_run_command(args, *, timeout, output_dir, output_prefix, **_kwargs):
        calls.append((args, timeout))
        return _cmd(args, '{"success": true, "issues": []}')

    monkeypatch.setattr(mythril_runner, "_myth_executable", lambda: "myth")
    monkeypatch.setattr(mythril_runner, "run_command", fake_run_command)

    res = mythril_runner.run_mythril(None, tmp_path, bytecode="0x6000", timeout=300)

    assert res.status == "ok"
    assert calls[0][1] == mythril_runner.MAX_EFFECTIVE_TIMEOUT
    args = calls[0][0]
    assert args[args.index("--execution-timeout") + 1] == "80"


def test_mythril_skips_large_bytecode_without_running(monkeypatch, tmp_path: Path):
    calls: list[list[str]] = []
    monkeypatch.setattr(mythril_runner, "_myth_executable", lambda: "myth")
    monkeypatch.setattr(
        mythril_runner,
        "run_command",
        lambda args, **_kwargs: calls.append(args) or _cmd(args, '{"success": true, "issues": []}'),
    )
    large_bytecode = "0x" + "60" * (mythril_runner.MAX_BYTECODE_FALLBACK_BYTES + 1)

    res = mythril_runner.run_mythril(None, tmp_path, bytecode=large_bytecode, timeout=300)

    assert res.status == "skipped"
    assert res.meta["bytecode_fallback_skipped"] == "too_large"
    assert "too large" in res.summary
    assert calls == []


def test_mythril_source_failure_skips_large_bytecode_fallback(monkeypatch, tmp_path: Path):
    calls: list[list[str]] = []

    def fake_run_command(args, *, timeout, output_dir, output_prefix, **_kwargs):
        calls.append(args)
        return _cmd(args, '{"success": false, "error": "compile failed", "issues": []}')

    source = tmp_path / "Target.sol"
    source.write_text("contract Target {}", encoding="utf-8")
    large_bytecode = "0x" + "60" * (mythril_runner.MAX_BYTECODE_FALLBACK_BYTES + 1)
    monkeypatch.setattr(mythril_runner, "_myth_executable", lambda: "myth")
    monkeypatch.setattr(mythril_runner, "run_command", fake_run_command)

    res = mythril_runner.run_mythril(source, tmp_path, bytecode=large_bytecode, timeout=300)

    assert res.status == "failed"
    assert res.meta["bytecode_fallback_skipped"] == "too_large"
    assert "bytecode fallback skipped" in res.summary
    assert len(calls) == 1
    assert str(source) in calls[0]
