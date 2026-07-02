"""Slither runner.

Runs Slither with an explicit, per-invocation solc binary. This avoids the
global ``solc-select use`` race where parallel scans can switch compiler
versions underneath each other.
"""
from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path

from ..core.command_runner import run_command, which
from .base import RunnerResult

logger = logging.getLogger("bulkauditai.slither")

# Detectors we care most about (others are still recorded, just not highlighted).
HIGH_VALUE_CHECKS = {
    "unprotected-upgrade",
    "controlled-delegatecall",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "reentrancy-eth",
    "reentrancy-no-eth",
    "unchecked-transfer",
    "unchecked-lowlevel",
    "tx-origin",
    "suicidal",
    "uninitialized-state",
    "uninitialized-storage",
    "shadowing-state",
    "incorrect-equality",
    "delegatecall-loop",
}


def _normalize(results_json: dict) -> list[dict]:
    findings: list[dict] = []
    detectors = (results_json.get("results") or {}).get("detectors") or []
    for d in detectors:
        impact = (d.get("impact") or "").lower()
        check = d.get("check") or ""
        # Keep High/Medium plus any high-value check regardless of impact.
        if impact not in ("high", "medium") and check not in HIGH_VALUE_CHECKS:
            continue
        elements = d.get("elements") or []
        location = ""
        if elements:
            sm = elements[0].get("source_mapping") or {}
            location = f"{sm.get('filename_short', '')}:{sm.get('lines', '')}"
        # Best-effort function name: a function-type element, else a node's parent.
        function = ""
        for el in elements:
            if (el.get("type") or "") == "function" and el.get("name"):
                function = el.get("name")
                break
        if not function:
            for el in elements:
                parent = (el.get("type_specific_fields") or {}).get("parent") or {}
                if (parent.get("type") or "") == "function" and parent.get("name"):
                    function = parent.get("name")
                    break
        findings.append(
            {
                "check": check,
                "impact": impact,
                "confidence": (d.get("confidence") or "").lower(),
                "description": (d.get("description") or "").strip()[:2000],
                "location": location,
                "function": function,
                "high_value": check in HIGH_VALUE_CHECKS,
            }
        )
    return findings


def run_slither(
    source_dir: Path,
    out_dir: Path,
    *,
    main_source: Path | None = None,
    solc_version: str | None = None,
    evm_version: str | None = None,
    optimizer_enabled: bool | None = None,
    optimizer_runs: int | None = None,
    timeout: int = 180,
) -> RunnerResult:
    if which("slither") is None:
        return RunnerResult.skipped("slither", "slither not installed (pip install slither-analyzer)")

    out_dir.mkdir(parents=True, exist_ok=True)
    source_dir = source_dir.resolve()
    out_dir = out_dir.resolve()
    if main_source is not None:
        main_source = main_source.resolve()

    meta = _read_meta(source_dir, main_source)
    solc_version = solc_version or meta.get("solc_version")
    evm_version = evm_version or meta.get("evm_version")
    if optimizer_enabled is None and "optimization_used" in meta:
        optimizer_enabled = bool(meta.get("optimization_used"))
    if optimizer_runs is None and meta.get("optimization_runs"):
        optimizer_runs = int(meta.get("optimization_runs") or 0)

    targets = _candidate_targets(source_dir, main_source)
    if not targets:
        return RunnerResult.skipped("slither", "no Solidity files to analyze")

    aggregate = {"success": True, "results": {"detectors": []}}
    commands = []
    last_result: RunnerResult | None = None
    failures: list[str] = []

    # Prefer the main contract. If it compiles, that gives the highest-signal
    # Slither result without burning time on every imported library.
    for i, target in enumerate(targets[:25]):
        ok, parsed, result, failure = _run_one(
            target,
            source_dir,
            out_dir,
            i,
            solc_version=solc_version,
            evm_version=evm_version,
            optimizer_enabled=optimizer_enabled,
            optimizer_runs=optimizer_runs,
            timeout=max(45, timeout if i == 0 else timeout // 3),
        )
        last_result = result
        commands.append(result.command)
        if ok and parsed is not None:
            aggregate["results"]["detectors"].extend(
                (parsed.get("results") or {}).get("detectors") or []
            )
            # If the primary file worked, stop. Fallback file-scanning is only
            # for compile-hostile layouts.
            if i == 0:
                break
        elif failure:
            failures.append(failure)

        # If a preferred main source failed, continue with the remaining project
        # files. Otherwise the cap keeps total run time bounded.

    if last_result is None:
        return RunnerResult.skipped("slither", "no Slither attempt was run")

    result = last_result
    result.command = commands[0] if len(commands) == 1 else " && ".join(commands[:3])
    result.json_output_path = str(_write_aggregate(out_dir, aggregate))
    result.findings = _normalize(aggregate)

    if aggregate["results"]["detectors"]:
        result.status = "ok"
    elif result.status == "failed" and not failures:
        result.status = "ok"

    if failures and not aggregate["results"]["detectors"]:
        result.status = "failed"
        result.summary = f"slither failed: {failures[-1][:220]}"
    else:
        high = [f for f in result.findings if f.get("high_value") or f.get("impact") == "high"]
        result.summary = f"{len(result.findings)} detector hits ({len(high)} high-value/high-impact)"
    return result


def _run_one(
    target: Path,
    source_dir: Path,
    out_dir: Path,
    index: int,
    *,
    solc_version: str | None,
    evm_version: str | None,
    optimizer_enabled: bool | None,
    optimizer_runs: int | None,
    timeout: int,
) -> tuple[bool, dict | None, RunnerResult, str]:
    attempts: list[tuple[str | None, bool | None]] = []
    for version in _solc_candidates(solc_version):
        attempts.append((version, optimizer_enabled))
    # Stack-too-deep is common on large 0.8.x verified contracts. A newer local
    # compiler with optimizer enabled often compiles the same source well enough
    # for Slither's static pass, while avoiding solc-bin network downloads.
    if _is_old_08(solc_version):
        attempts.append(("0.8.20", True))

    last_cmd = None
    last_failure = ""
    for attempt_no, (version, opt_enabled) in enumerate(attempts):
        json_out = out_dir / f"slither_{index}_{attempt_no}.json"
        _unlink(json_out)
        solc_bin = _solc_binary(version)
        args = [
            "slither",
            str(target),
            "--compile-force-framework",
            "solc",
        ]
        if solc_bin:
            args += ["--solc", solc_bin]
        remaps = _solc_remaps(source_dir)
        if remaps:
            args += ["--solc-remaps", " ".join(remaps)]
        solc_args = _solc_args(
            source_dir,
            target,
            version,
            evm_version,
            opt_enabled,
            optimizer_runs,
        )
        if solc_args:
            args += ["--solc-args", solc_args]
        args += ["--json", str(json_out)]

        cmd = run_command(
            args,
            timeout=timeout,
            cwd=_neutral_cwd(),
            output_dir=out_dir,
            output_prefix=f"slither_{index}_{attempt_no}",
        )
        last_cmd = cmd
        result = RunnerResult.from_command("slither", cmd)
        parsed = _parse_json(json_out)
        if parsed is not None and parsed.get("success") is True and _json_matches_source(parsed, source_dir):
            result.json_output_path = str(json_out)
            # Slither uses a nonzero exit code when it finds issues.
            result.status = "ok"
            return True, parsed, result, ""
        last_failure = _failure_text(cmd, parsed)
        if not _should_retry(last_failure):
            break

    fallback = RunnerResult.from_command("slither", last_cmd) if last_cmd else RunnerResult.skipped("slither", "not run")
    return False, None, fallback, last_failure


def _read_meta(source_dir: Path, main_source: Path | None) -> dict:
    paths: list[Path] = []
    if main_source is not None and "_implementation" in main_source.parts:
        paths.append(source_dir / "_implementation" / "_meta.json")
    paths.append(source_dir / "_meta.json")
    paths.append(source_dir / "_implementation" / "_meta.json")
    for path in paths:
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            continue
    return {}


def _neutral_cwd() -> Path:
    """Run Slither outside the repo/output tree so Foundry config is not probed.

    Crytic-compile may inspect the current directory for Foundry defaults even
    when we pass ``--compile-force-framework solc``. Running from a neutral temp
    directory keeps explicit ``--solc``, remappings, optimizer and EVM settings
    authoritative.
    """
    path = Path(tempfile.gettempdir()) / "bulkauditai-slither-cwd"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _candidate_targets(source_dir: Path, main_source: Path | None) -> list[Path]:
    targets: list[Path] = []
    if main_source is not None and main_source.exists():
        targets.append(main_source)
    all_sols = [p for p in source_dir.rglob("*.sol") if _is_project_source(p)]
    all_sols.sort(key=lambda p: p.stat().st_size if p.exists() else 0, reverse=True)
    for sol in all_sols:
        if sol not in targets:
            targets.append(sol)
    return targets


def _is_project_source(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if "node_modules" in parts:
        return False
    # Imports are compiled as dependencies; running Slither directly over a
    # library package is usually noisy and can crowd out the target contract.
    if "lib" in parts and "_implementation" not in parts:
        return False
    if "@openzeppelin" in parts or "openzeppelin-contracts" in parts:
        return False
    return True


def _solc_candidates(version: str | None) -> list[str | None]:
    out: list[str | None] = []
    if version:
        out.append(version)
    else:
        out.append(None)
        for candidate in ("0.8.20", "0.8.10", "0.6.10"):
            if _solc_binary(candidate):
                out.append(candidate)
    seen: set[str | None] = set()
    deduped: list[str | None] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _solc_binary(version: str | None) -> str | None:
    if not version:
        return which("solc")
    home = Path.home()
    candidates = [
        home / ".solc-select" / "artifacts" / f"solc-{version}" / f"solc-{version}",
        Path("/home/deploy") / ".solc-select" / "artifacts" / f"solc-{version}" / f"solc-{version}",
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate)
    if which("solc-select"):
        run_command(["solc-select", "install", version], timeout=180)
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return str(candidate)
    return which("solc")


def _solc_remaps(source_dir: Path) -> list[str]:
    remaps: list[str] = []
    seen_prefixes: set[str] = set()

    def add(prefix: str, path: Path) -> None:
        if not path.exists() or not path.is_dir():
            return
        if prefix in seen_prefixes:
            return
        seen_prefixes.add(prefix)
        value = f"{prefix}={path.resolve()}/"
        remaps.append(value)

    roots = [source_dir]
    impl_root = source_dir / "_implementation"
    if impl_root.exists():
        roots = [impl_root, source_dir]
    for root in roots:
        add("@openzeppelin/contracts/", root / "@openzeppelin" / "contracts")
        add("@openzeppelin/contracts-upgradeable/", root / "@openzeppelin" / "contracts-upgradeable")
        add("@openzeppelin/contracts/", root / "lib" / "openzeppelin-contracts" / "contracts")
        add(
            "@openzeppelin/contracts-upgradeable/",
            root / "lib" / "openzeppelin-contracts-upgradeable" / "contracts",
        )
        add("rollup-encoder/", root / "lib" / "rollup-encoder" / "src")
        lib_dir = root / "lib"
        if lib_dir.exists():
            for lib in lib_dir.iterdir():
                if not lib.is_dir():
                    continue
                add(f"{lib.name}/", lib / "src")
                add(f"{lib.name}/", lib / "contracts")
    return remaps


def _solc_args(
    source_dir: Path,
    target: Path,
    solc_version: str | None,
    evm_version: str | None,
    optimizer_enabled: bool | None,
    optimizer_runs: int | None,
) -> str:
    args: list[str] = []
    if optimizer_enabled:
        args.append("--optimize")
        if optimizer_runs:
            args += ["--optimize-runs", str(optimizer_runs)]
    evm = _clean_evm(evm_version) or _infer_evm(solc_version)
    if evm:
        args += ["--evm-version", evm]
    allow = [str(source_dir.resolve())]
    impl = source_dir / "_implementation"
    if impl.exists():
        allow.append(str(impl.resolve()))
    if target.parent.exists():
        allow.append(str(target.parent.resolve()))
    args += ["--allow-paths", ",".join(dict.fromkeys(allow))]
    return " ".join(args)


def _clean_evm(evm_version: str | None) -> str | None:
    evm = (evm_version or "").strip().lower()
    if not evm or evm == "default":
        return None
    if evm in {"osaka", "cancun", "prague"}:
        # Older installed solc builds reject newer explorer labels.
        return "london"
    return evm


def _infer_evm(solc_version: str | None) -> str | None:
    vt = _version_tuple(solc_version)
    if not vt:
        return None
    if vt >= (0, 8, 7):
        return "london"
    return "istanbul"


def _is_old_08(solc_version: str | None) -> bool:
    vt = _version_tuple(solc_version)
    return bool(vt and vt[0] == 0 and vt[1] == 8 and vt[2] < 20)


def _version_tuple(version: str | None) -> tuple[int, int, int] | None:
    if not version:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _should_retry(failure: str) -> bool:
    text = (failure or "").lower()
    return any(
        marker in text
        for marker in (
            "stack too deep",
            "invalid option for --evm-version",
            "requires different compiler version",
            "source file requires different compiler version",
            "compiler error",
        )
    )


def _failure_text(cmd, parsed: dict | None) -> str:
    if parsed is not None and parsed.get("success") is False:
        error = parsed.get("error") or parsed.get("stderr") or parsed.get("stdout")
        if error:
            return str(error).replace("\n", " ")[:500]
    out = f"{cmd.stderr or ''}\n{cmd.stdout or ''}".strip()
    return out.replace("\n", " ")[:500] or f"exit code {cmd.exit_code}"


def _json_matches_source(parsed: dict, source_dir: Path) -> bool:
    detectors = (parsed.get("results") or {}).get("detectors") or []
    if not detectors:
        return True
    source_root = source_dir.resolve()
    checked = 0
    for det in detectors:
        for el in det.get("elements") or []:
            sm = el.get("source_mapping") or {}
            filename = sm.get("filename_absolute") or sm.get("filename")
            if not filename:
                continue
            checked += 1
            try:
                Path(filename).resolve().relative_to(source_root)
            except Exception:
                return False
    return checked == 0 or True


def _write_aggregate(out_dir: Path, aggregate: dict) -> Path:
    path = out_dir / "slither.json"
    path.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    return path


def _parse_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None


def _unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
