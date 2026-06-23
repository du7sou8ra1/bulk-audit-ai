"""Scan orchestration.

A simple asyncio worker (MVP) runs the pipeline per target with bounded
concurrency. Progress is published to an in-memory hub that the WebSocket layer
subscribes to. One failing tool/step never aborts the scan — errors are stored.

Pipeline per target:
    fetch source/abi/bytecode -> resolve proxy -> (impl source) -> run tools
    -> build context -> run detectors -> score -> DeepSeek -> persist + report
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import re
from collections import defaultdict
from pathlib import Path

from sqlalchemy import select

from ..config import get_settings
from ..database import SessionLocal
from ..detectors.base import TargetContext
from ..detectors.registry import get_detectors
from ..models import (
    AIReview,
    Classification,
    Finding,
    Scan,
    ScanStatus,
    Target,
    TargetStatus,
    ToolRun,
    ToolStatus,
    utcnow,
)
from . import coverage as coverage_mod
from . import dedup
from . import evidence as evidence_mod
from . import flashloan_sim
from . import poc_generator
from . import report_writer
from .ai_reviewer import review_finding
from .command_runner import which
from .invariant_reasoner import run_invariant_reasoner
from .onchain import OnchainClient
from .proxy_resolver import resolve_proxy
from .refuter import refute as refute_finding
from .scoring import score_finding, mark_corroboration
from .source_fetcher import (
    SourcePackage,
    fetch_source,
    expand_module_sources,
    project_source_files,
    write_source_to_workspace,
)

logger = logging.getLogger("bulkauditai.scanner")


# --------------------------------------------------------------------------- #
# Progress hub (in-memory pub/sub for WebSocket / SSE)
# --------------------------------------------------------------------------- #
class ProgressHub:
    def __init__(self) -> None:
        self._subs: dict[int, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, scan_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs[scan_id].add(q)
        return q

    def unsubscribe(self, scan_id: int, q: asyncio.Queue) -> None:
        self._subs[scan_id].discard(q)

    def publish(self, scan_id: int, event: dict) -> None:
        for q in list(self._subs.get(scan_id, ())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:  # pragma: no cover - slow consumer
                pass


hub = ProgressHub()


# --------------------------------------------------------------------------- #
# Scan manager
# --------------------------------------------------------------------------- #
class ScanManager:
    def __init__(self) -> None:
        self._tasks: dict[int, asyncio.Task] = {}
        self._cancelled: set[int] = set()
        self._scan_sema = asyncio.Semaphore(get_settings().max_parallel_scans)
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Capture the main event loop at startup so SYNC FastAPI endpoints (which
        run in a threadpool, with no running loop) can still schedule scans."""
        self._loop = loop

    def start_scan(self, scan_id: int) -> None:
        if scan_id in self._tasks and not self._tasks[scan_id].done():
            return
        self._cancelled.discard(scan_id)

        def _spawn() -> None:
            self._tasks[scan_id] = asyncio.create_task(self._run_scan(scan_id))

        try:
            asyncio.get_running_loop()  # we're already on the event-loop thread
        except RuntimeError:
            # called from a worker thread (sync endpoint) -> schedule on main loop
            if self._loop is None:
                raise RuntimeError("scan manager event loop not set")
            self._loop.call_soon_threadsafe(_spawn)
        else:
            _spawn()

    def cancel_scan(self, scan_id: int) -> None:
        self._cancelled.add(scan_id)

    def is_cancelled(self, scan_id: int) -> bool:
        return scan_id in self._cancelled

    async def _run_scan(self, scan_id: int) -> None:
        async with self._scan_sema:
            try:
                await run_scan_pipeline(scan_id, self)
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("scan %s crashed: %s", scan_id, exc)
                _mark_scan_failed(scan_id, str(exc))
                hub.publish(scan_id, {"type": "scan_update", "status": "failed", "error": str(exc)})


manager = ScanManager()


# --------------------------------------------------------------------------- #
# DB helpers
# --------------------------------------------------------------------------- #
def _mark_scan_failed(scan_id: int, error: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error = error[:2000]
            scan.finished_at = utcnow()
            db.commit()


def _recompute_scan_counts(db, scan: Scan) -> None:
    target_ids = [t.id for t in db.scalars(select(Target).where(Target.scan_id == scan.id))]
    findings = (
        db.scalars(select(Finding).where(Finding.target_id.in_(target_ids))).all()
        if target_ids
        else []
    )
    crit = sum(
        1
        for f in findings
        if f.classification
        in (Classification.CONFIRMED_CRITICAL, Classification.LIKELY_CRITICAL_NEEDS_POC)
    )
    needs = sum(1 for f in findings if f.classification == Classification.NEEDS_MORE_INVESTIGATION)
    low = sum(1 for f in findings if f.classification == Classification.LOW_OR_INFO)
    fp = sum(1 for f in findings if f.classification == Classification.FALSE_POSITIVE)
    scan.critical_count = crit
    scan.needs_investigation_count = needs
    scan.low_info_count = low
    scan.false_positive_count = fp


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
async def run_scan_pipeline(scan_id: int, mgr: ScanManager) -> None:
    s = get_settings()
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        db.commit()
        target_ids = [t.id for t in db.scalars(select(Target).where(Target.scan_id == scan_id))]
        profile = scan.scan_profile
        chain = scan.chain
        toggles = dict(scan.toggles or {})

    hub.publish(scan_id, {"type": "scan_update", "status": "running"})

    target_sema = asyncio.Semaphore(max(1, s.max_parallel_targets))

    async def process(tid: int) -> None:
        async with target_sema:
            if mgr.is_cancelled(scan_id):
                return
            try:
                await process_target(scan_id, tid, profile, chain, toggles, mgr)
            except Exception as exc:  # one bad target must not abort the scan
                logger.exception("target %s failed: %s", tid, exc)
                _set_target_status(scan_id, tid, TargetStatus.FAILED, error=str(exc)[:2000])
                _log(scan_id, f"target {tid} failed: {exc}")

    await asyncio.gather(*(process(tid) for tid in target_ids))

    # Finalize.
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.completed_targets = _count_done(db, scan_id)
        _recompute_scan_counts(db, scan)
        if mgr.is_cancelled(scan_id):
            scan.status = ScanStatus.CANCELLED
        else:
            scan.status = ScanStatus.COMPLETED
        scan.finished_at = utcnow()
        db.commit()
        status = scan.status
    hub.publish(scan_id, {"type": "scan_update", "status": status})


def _set_target_status(scan_id: int, target_id: int, status: str, **extra) -> None:
    with SessionLocal() as db:
        t = db.get(Target, target_id)
        if not t:
            return
        t.status = status
        for k, v in extra.items():
            setattr(t, k, v)
        db.commit()
        addr = t.address
    hub.publish(
        scan_id,
        {"type": "target_update", "target_id": target_id, "address": addr, "status": status, **extra},
    )


def _log(scan_id: int, message: str) -> None:
    hub.publish(scan_id, {"type": "log", "message": message, "ts": dt.datetime.now(dt.timezone.utc).isoformat()})


async def process_target(
    scan_id: int, target_id: int, profile: str, chain: str, toggles: dict, mgr: ScanManager
) -> None:
    s = get_settings()
    onchain = OnchainClient(chain=chain)

    with SessionLocal() as db:
        t = db.get(Target, target_id)
        address = t.address

    _log(scan_id, f"[{address}] starting")
    _set_target_status(scan_id, target_id, TargetStatus.FETCHING)

    workspace = evidence_mod.create_target_workspace(scan_id, address)

    # --- Fetch source / ABI ------------------------------------------------ #
    try:
        pkg = await asyncio.to_thread(fetch_source, address, chain)
    except Exception as exc:
        logger.warning("source fetch failed for %s: %s", address, exc)
        pkg = SourcePackage(address=address, error=str(exc))
    write_source_to_workspace(workspace["source"], pkg)

    source_files: dict[str, str] = dict(pkg.source_files)
    contract_name = pkg.contract_name
    solc_version = pkg.solc_version

    # --- Bytecode + proxy resolution -------------------------------------- #
    _set_target_status(scan_id, target_id, TargetStatus.RESOLVING)
    bytecode = await asyncio.to_thread(onchain.get_code, address)
    balance = await asyncio.to_thread(onchain.get_balance_eth, address)
    proxy_info = await asyncio.to_thread(
        resolve_proxy, onchain, address, pkg.abi, pkg.implementation
    )

    # Fetch implementation source too, if proxy.
    impl_pkg: SourcePackage | None = None
    if proxy_info.implementation:
        try:
            impl_pkg = await asyncio.to_thread(
                fetch_source, proxy_info.implementation, chain
            )
            impl_dir = workspace["source"] / "_implementation"
            write_source_to_workspace(impl_dir, impl_pkg)
            for relp, content in impl_pkg.source_files.items():
                source_files[f"_implementation/{relp}"] = content
            if impl_pkg.contract_name:
                contract_name = contract_name or impl_pkg.contract_name
            solc_version = solc_version or impl_pkg.solc_version
        except Exception as exc:
            logger.warning("impl source fetch failed for %s: %s", address, exc)

    # --- Module / facet expansion (Diamond loupe + module dispatcher) ------ #
    # Dispatcher/diamond architectures keep logic in separate facet/module impls.
    # Pull them so detectors actually see the code (Euler donateToReserves
    # visibility gap + any EIP-2535 diamond such as Beanstalk).
    try:
        mod_files, expanded_modules = await asyncio.to_thread(
            expand_module_sources, onchain, address, chain, pkg.abi
        )
        if mod_files:
            source_files.update(mod_files)
            for relp, content in mod_files.items():
                fp = workspace["source"] / relp
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(content or "", encoding="utf-8", errors="replace")
            _log(scan_id, f"[{address}] expanded {len(expanded_modules)} facet/module impl(s)")
    except Exception as exc:
        logger.warning("module/facet expansion failed for %s: %s", address, exc)

    _set_target_status(
        scan_id,
        target_id,
        TargetStatus.DETECTING,
        source_verified=bool(pkg.verified or (impl_pkg and impl_pkg.verified)),
        contract_name=contract_name,
        is_proxy=proxy_info.is_proxy,
        proxy_type=proxy_info.proxy_type,
        implementation_address=proxy_info.implementation,
        proxy_admin=proxy_info.admin,
        owner=proxy_info.admin_owner or proxy_info.owner,
        balance_eth=balance,
        workspace_path=str(workspace["base"]),
    )

    # --- Run static tools -------------------------------------------------- #
    _set_target_status(scan_id, target_id, TargetStatus.TOOLS)
    tool_outputs: dict = {}
    have_source = bool(source_files)
    main_source = _pick_main_source(workspace["source"], contract_name) if have_source else None

    if _toggle(toggles, "slither", s.enable_slither):
        await _run_tool(
            scan_id, target_id, "slither", tool_outputs, workspace,
            have_source, main_source, bytecode, solc_version,
        )
    if _toggle(toggles, "semgrep", s.enable_semgrep):
        await _run_tool(
            scan_id, target_id, "semgrep", tool_outputs, workspace,
            have_source, main_source, bytecode, solc_version,
        )
    if _toggle(toggles, "mythril", s.enable_mythril):
        await _run_tool(
            scan_id, target_id, "mythril", tool_outputs, workspace,
            have_source, main_source, bytecode, solc_version,
        )

    # --- Detectors --------------------------------------------------------- #
    ctx = TargetContext(
        address=address,
        chain=chain,
        profile=profile,
        onchain=onchain,
        proxy_info=proxy_info,
        workspace=workspace["base"],
        contract_name=contract_name or "",
        # Detectors/reasoner see PROJECT code only (skip audited OZ/Solady libs);
        # the static tools still compile the full set from the workspace.
        source_files=project_source_files(source_files),
        abi=pkg.abi if pkg.abi is not None else (impl_pkg.abi if impl_pkg else None),
        bytecode=bytecode,
        tool_outputs=tool_outputs,
    )

    all_tool_findings = [
        f for out in tool_outputs.values() for f in (out.get("findings") or [])
    ]

    candidates = []
    detectors_run: list[str] = []
    for det in get_detectors(profile):
        detectors_run.append(det.name)
        try:
            found = await asyncio.to_thread(det.run, ctx)
            candidates.extend(found)
            if found:
                _log(scan_id, f"[{address}] {det.name}: {len(found)} candidate(s)")
        except Exception as exc:
            logger.warning("detector %s failed on %s: %s", det.name, address, exc)
            _log(scan_id, f"[{address}] detector {det.name} error: {exc}")

    # --- Semantic invariant reasoning (gap #1): LLM hunts cross-function ---- #
    reasoner_meta: dict = {}
    if _toggle(toggles, "invariant_reasoner", s.enable_invariant_reasoner) and source_files:
        _log(scan_id, f"[{address}] invariant reasoner: analyzing value-moving functions")
        try:
            hyps, reasoner_meta = await asyncio.to_thread(run_invariant_reasoner, ctx)
            if hyps:
                detectors_run.append("invariant_reasoner")
                candidates.extend(hyps)
                _log(scan_id, f"[{address}] invariant reasoner: {len(hyps)} hypothesis(es)")
            elif reasoner_meta.get("skipped") or reasoner_meta.get("error"):
                _log(scan_id, f"[{address}] invariant reasoner skipped: "
                              f"{reasoner_meta.get('skipped') or reasoner_meta.get('error')}")
        except Exception as exc:
            logger.warning("invariant reasoner failed on %s: %s", address, exc)
            _log(scan_id, f"[{address}] invariant reasoner error: {exc}")

    # Cross-signal corroboration: mark findings that >=2 independent detectors /
    # the reasoner flagged on the same function (scoring then bumps confidence).
    mark_corroboration(candidates)
    # Collapse cross-file duplicates (same finding from proxy+impl+flattened) so a
    # report is readable. Runs AFTER corroboration so it sees every copy.
    before_dedup = len(candidates)
    candidates = dedup.collapse_duplicates(candidates)
    if len(candidates) < before_dedup:
        _log(scan_id, f"[{address}] dedup: {before_dedup} -> {len(candidates)} findings")

    # --- Score + (optional) refute + fork PoC + AI review + persist ------- #
    _set_target_status(scan_id, target_id, TargetStatus.AI)
    deepseek_on = _toggle(toggles, "deepseek", s.enable_deepseek)
    foundry_on = _toggle(toggles, "foundry", s.enable_foundry)
    poc_capable = (
        foundry_on and onchain.available and bool(s.rpc_url) and which("forge") is not None
    )
    MAX_POCS_PER_TARGET = 3
    poc_count = 0
    flashsim_on = (
        poc_capable
        and _toggle(toggles, "flashloan_sim", s.enable_flashloan_sim)
    )
    sim_count = 0

    refute_on = _toggle(toggles, "refutation", s.enable_refutation)
    for i, cand in enumerate(candidates):
        if mgr.is_cancelled(scan_id):
            break

        # FP-learning (dedup): a candidate matching a user-marked false-positive
        # fingerprint is suppressed and skips every expensive step below.
        suppressed = dedup.apply_suppression(cand, address)
        if suppressed:
            _log(scan_id, f"[{address}] suppressed (known FP): {cand.title[:70]}")

        # Adversarial refutation (gap #3): an independent skeptic reads the code
        # and tries to DISPROVE the finding before it is scored. Skip pure-info
        # notes and weak candidates to save tokens.
        if refute_on and not suppressed and not (cand.evidence or {}).get("informational") and cand.impact_score >= 5:
            try:
                await asyncio.to_thread(refute_finding, ctx, cand)
                if (cand.evidence or {}).get("refuted"):
                    _log(scan_id, f"[{address}] refuted: {cand.title[:80]}")
            except Exception as exc:
                logger.warning("refuter failed on %s: %s", address, exc)

        score = score_finding(cand, all_tool_findings, profile=profile)

        # Generate + run a read-only fork PoC for strong, eligible candidates.
        if (
            poc_capable
            and not suppressed
            and poc_count < MAX_POCS_PER_TARGET
            and poc_generator.is_poc_eligible(cand, score)
        ):
            poc_dir = workspace["foundry"] / f"poc_{i}"
            _log(
                scan_id,
                f"[{address}] generating fork PoC for {cand.detector}:"
                f"{(cand.affected_functions or ['?'])[0]}",
            )
            poc = await asyncio.to_thread(
                poc_generator.generate_and_run,
                ctx, cand, poc_dir, rpc_url=s.rpc_url, timeout=s.foundry_timeout,
            )
            if poc.get("generated"):
                poc_count += 1
                cand.evidence["poc_passed"] = bool(poc.get("passed"))
                cand.evidence["poc"] = {
                    "signature": poc.get("signature"),
                    "note": poc.get("note"),
                    "runner_status": poc.get("runner_status"),
                    "is_upgrade": poc.get("is_upgrade"),
                }
                runner = poc.get("runner")
                if runner is not None:
                    tr = _create_toolrun(target_id, "foundry-poc")
                    _finalize_toolrun(tr.id, runner)
                    hub.publish(
                        scan_id,
                        {"type": "tool_update", "target_id": target_id,
                         "tool": "foundry-poc", "status": runner.status, "summary": poc.get("note")},
                    )
                score = score_finding(cand, all_tool_findings, profile=profile)  # re-score with PoC
                _log(
                    scan_id,
                    f"[{address}] PoC {'PASSED' if poc.get('passed') else 'inconclusive'}: "
                    f"{poc.get('note')}",
                )

        # State-invariant PoC scaffold (gap #2) for accounting/settlement classes
        # — a compiling skeleton the user completes (never auto-counted as passing).
        if poc_generator.is_state_invariant_finding(cand) and not suppressed and cand.affected_functions:
            try:
                sc = poc_generator.write_state_scaffold(
                    ctx, cand, workspace["foundry"] / f"scaffold_{i}"
                )
                cand.evidence["state_poc_scaffold"] = sc.get("path")
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("scaffold write failed: %s", exc)

        # Fork oracle/flash-loan manipulation sim (gap: validation) — confirms the
        # donation/balanceOf-manipulable price class; scaffolds the AMM case.
        if (
            flashsim_on
            and not suppressed
            and sim_count < s.max_sims_per_target
            and flashloan_sim.is_sim_eligible(cand)
        ):
            sim_dir = workspace["foundry"] / f"sim_{i}"
            _log(scan_id, f"[{address}] oracle-manipulation fork sim for {cand.detector}")
            sim = await asyncio.to_thread(
                flashloan_sim.generate_and_run,
                ctx, cand, sim_dir, rpc_url=s.rpc_url, timeout=s.foundry_timeout,
            )
            sim_count += 1
            cand.evidence["oracle_sim"] = {
                "manipulable": sim.get("manipulable"),
                "note": sim.get("note"),
                "price_fn": sim.get("price_fn"),
                "scaffold": sim.get("scaffold", False),
            }
            if sim.get("manipulable"):
                cand.evidence["poc_passed"] = True
                cand.evidence["manipulation_confirmed"] = True
                runner = sim.get("runner")
                if runner is not None:
                    tr = _create_toolrun(target_id, "oracle-sim")
                    _finalize_toolrun(tr.id, runner)
                    hub.publish(scan_id, {
                        "type": "tool_update", "target_id": target_id, "tool": "oracle-sim",
                        "status": runner.status, "summary": sim.get("note")})
                score = score_finding(cand, all_tool_findings, profile=profile)  # re-score with confirmation
                _log(scan_id, f"[{address}] ORACLE MANIPULATION CONFIRMED: {sim.get('note')}")

        packet = evidence_mod.build_ai_packet(ctx, cand, score)
        slug = _finding_slug(cand.detector, i, (cand.affected_functions or [None])[0])
        evidence_mod.write_finding_evidence(workspace, slug, cand, packet)

        ai_result = None
        if deepseek_on and not suppressed:
            prompt_path = workspace["ai"] / f"{slug}.prompt.txt"
            ai_result = await asyncio.to_thread(
                review_finding, packet, prompt_save_path=prompt_path
            )
            try:
                (workspace["ai"] / f"{slug}.response.json").write_text(
                    _safe_json(ai_result.response_json), encoding="utf-8"
                )
            except OSError as exc:  # pragma: no cover - defensive
                logger.warning("ai response write failed: %s", exc)

        _persist_finding(scan_id, target_id, cand, score, ai_result, workspace)

    # --- Coverage accounting (gap #6): make "0 findings" honestly scoped --- #
    try:
        tool_statuses = {t: (o.get("status") or "?") for t, o in tool_outputs.items()}
        cov = coverage_mod.build_coverage(
            ctx,
            detectors_run=detectors_run,
            tool_statuses=tool_statuses,
            candidate_count=len(candidates),
            source_verified=bool(pkg.verified or (impl_pkg and impl_pkg.verified)),
            reasoner_meta=reasoner_meta,
        )
        (workspace["base"] / "coverage.json").write_text(_safe_json(cov), encoding="utf-8")
        _log(scan_id, f"[{address}] coverage: {cov['honest_summary']}")
        hub.publish(scan_id, {"type": "coverage", "target_id": target_id,
                              "address": address, "coverage": cov})
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("coverage build failed for %s: %s", address, exc)

    _set_target_status(scan_id, target_id, TargetStatus.COMPLETED)
    _log(scan_id, f"[{address}] done ({len(candidates)} candidates)")

    # Update scan completed counter + recompute classification counts.
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.completed_targets = _count_done(db, scan_id)
            _recompute_scan_counts(db, scan)
            db.commit()
            progress = {
                "completed": scan.completed_targets,
                "total": scan.total_targets,
                "critical": scan.critical_count,
            }
    hub.publish(scan_id, {"type": "progress", **progress})


def _count_done(db, scan_id: int) -> int:
    rows = db.scalars(
        select(Target).where(
            Target.scan_id == scan_id,
            Target.status.in_([TargetStatus.COMPLETED, TargetStatus.FAILED, TargetStatus.SKIPPED]),
        )
    ).all()
    return len(rows)


# --------------------------------------------------------------------------- #
# Tool execution + persistence helpers
# --------------------------------------------------------------------------- #
def _toggle(toggles: dict, key: str, default: bool) -> bool:
    val = toggles.get(key)
    return default if val is None else bool(val)


def _finding_slug(detector: str, index: int, fn: str | None) -> str:
    """Filesystem-safe slug for a finding's evidence/AI files. Function names from
    the LLM reasoner can contain '/', spaces, etc. that would break the path."""
    raw = f"{detector}_{index}_{fn or 'x'}"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", raw)[:120]


def _pick_main_source(source_dir: Path, contract_name: str | None) -> Path | None:
    sols = [p for p in source_dir.rglob("*.sol") if "_implementation" not in p.parts] or list(
        source_dir.rglob("*.sol")
    )
    if not sols:
        return None
    if contract_name:
        for p in sols:
            if p.stem == contract_name:
                return p
    # Fallback: the largest file (usually the main contract).
    return max(sols, key=lambda p: p.stat().st_size if p.exists() else 0)


async def _run_tool(
    scan_id, target_id, tool, tool_outputs, workspace, have_source, main_source, bytecode, solc_version
) -> None:
    from ..runners.mythril_runner import run_mythril
    from ..runners.semgrep_runner import run_semgrep
    from ..runners.slither_runner import run_slither

    s = get_settings()
    tr = _create_toolrun(target_id, tool)
    hub.publish(scan_id, {"type": "tool_update", "target_id": target_id, "tool": tool, "status": "running"})

    try:
        if tool == "slither":
            if not have_source:
                res = _skip_runner(tool, "no verified source to compile")
            else:
                res = await asyncio.to_thread(
                    run_slither, workspace["source"], workspace["slither"],
                    solc_version=solc_version, timeout=s.slither_timeout,
                )
        elif tool == "semgrep":
            if not have_source:
                res = _skip_runner(tool, "no source to scan")
            else:
                res = await asyncio.to_thread(
                    run_semgrep, workspace["source"], workspace["semgrep"], timeout=s.semgrep_timeout
                )
        elif tool == "mythril":
            res = await asyncio.to_thread(
                run_mythril, main_source, workspace["mythril"],
                bytecode=bytecode, solc_version=solc_version, timeout=s.mythril_timeout,
            )
        else:
            res = _skip_runner(tool, "unknown tool")
    except Exception as exc:
        logger.warning("tool %s crashed on target %s: %s", tool, target_id, exc)
        res = _skip_runner(tool, f"runner crashed: {exc}")
        res.status = "failed"

    tool_outputs[tool] = {"summary": res.summary, "findings": res.findings, "status": res.status}
    _finalize_toolrun(tr.id, res)
    hub.publish(
        scan_id,
        {"type": "tool_update", "target_id": target_id, "tool": tool, "status": res.status, "summary": res.summary},
    )


def _skip_runner(tool: str, reason: str):
    from ..runners.base import RunnerResult

    return RunnerResult.skipped(tool, reason)


def _create_toolrun(target_id: int, tool: str) -> ToolRun:
    with SessionLocal() as db:
        tr = ToolRun(target_id=target_id, tool_name=tool, status=ToolStatus.RUNNING, started_at=utcnow())
        db.add(tr)
        db.commit()
        db.refresh(tr)
        return tr


def _finalize_toolrun(toolrun_id: int, res) -> None:
    status_map = {
        "ok": ToolStatus.OK,
        "failed": ToolStatus.FAILED,
        "timeout": ToolStatus.TIMEOUT,
        "skipped": ToolStatus.SKIPPED,
    }
    with SessionLocal() as db:
        tr = db.get(ToolRun, toolrun_id)
        if not tr:
            return
        tr.status = status_map.get(res.status, ToolStatus.FAILED)
        tr.finished_at = utcnow()
        tr.command = res.command
        tr.exit_code = res.exit_code
        tr.timed_out = res.timed_out
        tr.stdout_path = res.stdout_path
        tr.stderr_path = res.stderr_path
        tr.json_output_path = res.json_output_path
        tr.summary = res.summary
        db.commit()


def _persist_finding(scan_id, target_id, cand, score, ai_result, workspace) -> None:
    with SessionLocal() as db:
        finding = Finding(
            target_id=target_id,
            detector=cand.detector,
            title=cand.title,
            severity_candidate=score.severity_candidate,
            confidence_before_ai=score.confidence_before_ai,
            impact_score=score.impact_score,
            confidence_score=score.confidence_score,
            status="open",
            classification=score.classification,
            description=cand.description,
            evidence_json={**(cand.evidence or {}), "affected_functions": cand.affected_functions},
            next_tests_json=cand.next_tests,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        if ai_result is not None:
            ai = AIReview(
                finding_id=finding.id,
                model=ai_result.model,
                prompt_path=str(workspace["ai"]),
                request_json=ai_result.request_json,
                response_json=ai_result.response_json if ai_result.error is None else {"error": ai_result.error},
                classification=ai_result.classification,
                rationale=ai_result.rationale or ai_result.error,
                recommended_next_steps=ai_result.next_tests,
            )
            db.add(ai)
            db.commit()
            db.refresh(ai)
            finding.ai_review_id = ai.id
            # AI verdict supersedes the pre-AI classification when present.
            if ai_result.classification and ai_result.error is None:
                finding.classification = ai_result.classification
            db.commit()

        # Generate a report draft for reportable findings.
        target = db.get(Target, target_id)
        ai_row = db.get(AIReview, finding.ai_review_id) if finding.ai_review_id else None
        try:
            report_writer.write_report(finding, target, ai_row, workspace["reports"])
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("report write failed: %s", exc)

        hub.publish(
            scan_id,
            {
                "type": "finding",
                "target_id": target_id,
                "finding_id": finding.id,
                "detector": finding.detector,
                "classification": finding.classification,
                "impact": finding.impact_score,
                "confidence": finding.confidence_score,
            },
        )

        # "Before-drain" alert: a confirmed critical pages a human immediately.
        if finding.classification == Classification.CONFIRMED_CRITICAL:
            try:
                from . import alerting

                alerting.send_alert(
                    f"CONFIRMED CRITICAL: {finding.title[:120]}",
                    f"target={target.address} detector={finding.detector} "
                    f"impact={finding.impact_score} confidence={finding.confidence_score}",
                    severity="critical",
                    context={"scan_id": scan_id, "finding_id": finding.id,
                             "address": target.address},
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("critical alert failed: %s", exc)


def _safe_json(obj) -> str:
    import json

    try:
        return json.dumps(obj, indent=2, default=str)
    except Exception:
        return "{}"
