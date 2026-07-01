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
from .audit_knowledge import annotate_candidate
from . import bytecode_intel
from . import bytecode_probes
from .candidate_sanity import apply_candidate_sanity
from . import dedup
from . import evidence as evidence_mod
from . import flashloan_sim
from . import fuzzing
from . import poc_generator
from . import protocol_graph as protocol_graph_mod
from . import report_writer
from .ai_reviewer import review_finding
from .command_runner import which
from .invariant_reasoner import run_invariant_reasoner
from .onchain import OnchainClient
from .proxy_resolver import resolve_proxy
from .refuter import refute as refute_finding
from .semantic_index import build_semantic_index
from .taint import analyze_taint
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

    # Phase 12: merge per-target protocol graphs into a scan-level view.
    try:
        scan_graph = await asyncio.to_thread(
            protocol_graph_mod.write_scan_protocol_graph,
            scan_id,
            get_settings().output_path / str(scan_id),
        )
        summary = scan_graph.get("summary") or {}
        _log(
            scan_id,
            "protocol graph: "
            f"{summary.get('target_graph_count', 0)} target graph(s), "
            f"{summary.get('surface_count', 0)} surface(s), "
            f"{summary.get('companion_candidate_count', 0)} companion candidate(s)",
        )
        hub.publish(scan_id, {"type": "scan_update", "protocol_graph": scan_graph})
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("scan protocol graph merge failed for %s: %s", scan_id, exc)

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
    evm_version = pkg.evm_version
    optimizer_enabled = pkg.optimization_used
    optimizer_runs = pkg.optimization_runs

    # --- Bytecode + proxy resolution -------------------------------------- #
    _set_target_status(scan_id, target_id, TargetStatus.RESOLVING)
    bytecode = await asyncio.to_thread(onchain.get_code, address)
    tool_bytecode = bytecode
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
            if impl_pkg.verified:
                if impl_pkg.contract_name:
                    contract_name = impl_pkg.contract_name
                solc_version = impl_pkg.solc_version or solc_version
                evm_version = impl_pkg.evm_version or evm_version
                optimizer_enabled = impl_pkg.optimization_used
                optimizer_runs = impl_pkg.optimization_runs or optimizer_runs
                try:
                    tool_bytecode = await asyncio.to_thread(onchain.get_code, proxy_info.implementation)
                except Exception as exc:  # pragma: no cover - network defensive
                    logger.warning("implementation bytecode fetch failed for %s: %s", address, exc)
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
    prefer_impl = bool(impl_pkg and impl_pkg.verified and proxy_info.implementation)
    main_source = (
        _pick_main_source(workspace["source"], contract_name, prefer_implementation=prefer_impl)
        if have_source
        else None
    )

    if _toggle(toggles, "slither", s.enable_slither):
        await _run_tool(
            scan_id, target_id, "slither", tool_outputs, workspace,
            have_source, main_source, tool_bytecode, solc_version,
            evm_version, optimizer_enabled, optimizer_runs,
        )
    if _toggle(toggles, "semgrep", s.enable_semgrep):
        await _run_tool(
            scan_id, target_id, "semgrep", tool_outputs, workspace,
            have_source, main_source, tool_bytecode, solc_version,
            evm_version, optimizer_enabled, optimizer_runs,
        )
    if _toggle(toggles, "mythril", s.enable_mythril):
        await _run_tool(
            scan_id, target_id, "mythril", tool_outputs, workspace,
            have_source, main_source, tool_bytecode, solc_version,
            evm_version, optimizer_enabled, optimizer_runs,
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
        abi=_combine_abis(pkg.abi, impl_pkg.abi if impl_pkg else None),
        bytecode=bytecode,
        tool_outputs=tool_outputs,
    )

    try:
        ctx.semantic = build_semantic_index(ctx.source_files, ctx.abi)
        tool_outputs["semantic-index"] = {
            "status": "ok",
            "findings": [],
            "meta": {
                "functions": len(ctx.semantic.functions_by_key),
                "entrypoints": sorted(ctx.semantic.entrypoints)[:80],
                "state_vars": len(ctx.semantic.state_vars),
                "mappings": len(ctx.semantic.mappings),
            },
        }
    except Exception as exc:
        logger.warning("semantic index failed for %s: %s", address, exc)
        ctx.semantic = None
        ctx.taint = None
        tool_outputs["semantic-index"] = {
            "status": "failed",
            "findings": [],
            "meta": {"error": str(exc)[:500]},
        }
    else:
        try:
            ctx.taint = analyze_taint(ctx.semantic)
            tool_outputs["taint"] = {
                "status": "ok",
                "findings": [],
                "meta": _taint_summary(ctx.taint),
            }
        except Exception as exc:
            logger.warning("taint analysis failed for %s: %s", address, exc)
            ctx.taint = None
            tool_outputs["taint"] = {
                "status": "failed",
                "findings": [],
                "meta": {"error": str(exc)[:500]},
            }

    # Phase 12: protocol-role graph. Runs after semantic facts so it can group
    # oracle/controller/market/vault/AMM/bridge companions and expose scan
    # candidates before detector scoring.
    tr = _create_toolrun(target_id, "protocol-graph")
    hub.publish(
        scan_id,
        {"type": "tool_update", "target_id": target_id, "tool": "protocol-graph", "status": "running"},
    )
    try:
        graph_res = await asyncio.to_thread(
            protocol_graph_mod.run_protocol_graph, ctx, workspace["base"]
        )
        ctx.protocol_graph = graph_res.meta
        tool_outputs["protocol-graph"] = {
            "summary": graph_res.summary,
            "findings": graph_res.findings,
            "status": graph_res.status,
            "meta": graph_res.meta,
        }
        _finalize_toolrun(tr.id, graph_res)
        _log(scan_id, f"[{address}] {graph_res.summary}")
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "protocol-graph",
             "status": graph_res.status, "summary": graph_res.summary},
        )
    except Exception as exc:
        logger.warning("protocol graph failed for %s: %s", address, exc)
        ctx.protocol_graph = None
        graph_res = _skip_runner("protocol-graph", f"runner crashed: {exc}")
        graph_res.status = "failed"
        tool_outputs["protocol-graph"] = {
            "summary": graph_res.summary,
            "findings": [],
            "status": graph_res.status,
            "meta": {"error": str(exc)[:500]},
        }
        _finalize_toolrun(tr.id, graph_res)
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "protocol-graph",
             "status": graph_res.status, "summary": graph_res.summary},
        )

    if _toggle(toggles, "value_context", s.enable_value_context):
        try:
            value_context = await asyncio.to_thread(
                onchain.probe_value_context,
                address,
                abi=ctx.abi,
                source_text=ctx.all_source_text(),
                referenced_by=None,
                contract_name=ctx.contract_name,
            )
        except Exception as exc:
            logger.warning("value-context probe failed for %s: %s", address, exc)
            value_context = {
                "state": "unknown",
                "signal": "unknown",
                "notes": [f"value-context probe failed: {exc}"],
            }
        tool_outputs["value-context"] = {"status": "ok", "findings": [], "meta": value_context}

    if _toggle(toggles, "bytecode_intel", s.enable_bytecode_intel):
        tr = _create_toolrun(target_id, "bytecode-intel")
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "bytecode-intel", "status": "running"},
        )
        try:
            _log(scan_id, f"[{address}] bytecode-intel: selector/opcode/decompiler-lite pass")
            bytecode_res = await asyncio.to_thread(
                bytecode_intel.run_bytecode_intel,
                bytecode=bytecode,
                out_dir=workspace["bytecode"],
                address=address,
                chain=chain,
                source_verified=bool(pkg.verified or (impl_pkg and impl_pkg.verified)),
                proxy_info=proxy_info.to_dict(),
            )
        except Exception as exc:
            logger.warning("bytecode-intel failed on %s: %s", address, exc)
            bytecode_res = _skip_runner("bytecode-intel", f"runner crashed: {exc}")
            bytecode_res.status = "failed"
        tool_outputs["bytecode-intel"] = {
            "summary": bytecode_res.summary,
            "findings": bytecode_res.findings,
            "status": bytecode_res.status,
            "meta": bytecode_res.meta,
        }
        _finalize_toolrun(tr.id, bytecode_res)
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "bytecode-intel",
             "status": bytecode_res.status, "summary": bytecode_res.summary},
        )

    if _toggle(toggles, "bytecode_probes", s.enable_bytecode_probes):
        tr = _create_toolrun(target_id, "bytecode-probes")
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "bytecode-probes", "status": "running"},
        )
        try:
            _log(scan_id, f"[{address}] bytecode-probes: selector-specific fork probe plan")
            probe_res = await asyncio.to_thread(
                bytecode_probes.run_bytecode_probes,
                bytecode_meta=(tool_outputs.get("bytecode-intel") or {}).get("meta"),
                out_dir=workspace["bytecode_probes"],
                address=address,
                chain=chain,
            )
        except Exception as exc:
            logger.warning("bytecode-probes failed on %s: %s", address, exc)
            probe_res = _skip_runner("bytecode-probes", f"runner crashed: {exc}")
            probe_res.status = "failed"
        tool_outputs["bytecode-probes"] = {
            "summary": probe_res.summary,
            "findings": probe_res.findings,
            "status": probe_res.status,
            "meta": probe_res.meta,
        }
        _finalize_toolrun(tr.id, probe_res)
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "bytecode-probes",
             "status": probe_res.status, "summary": probe_res.summary},
        )

    if _toggle(toggles, "fuzzing", s.enable_fuzzing):
        tr = _create_toolrun(target_id, "fuzzing")
        hub.publish(scan_id, {"type": "tool_update", "target_id": target_id, "tool": "fuzzing", "status": "running"})
        if not have_source:
            fuzz_res = _skip_runner("fuzzing", "no verified source/ABI to build fuzz readiness")
        else:
            try:
                _log(scan_id, f"[{address}] fuzzing: readiness + starter suite generation")
                fuzz_res = await asyncio.to_thread(
                    fuzzing.run_fuzzing,
                    ctx,
                    source_dir=workspace["source"],
                    out_dir=workspace["fuzz"],
                    timeout=s.fuzz_timeout,
                )
            except Exception as exc:
                logger.warning("fuzzing failed on %s: %s", address, exc)
                fuzz_res = _skip_runner("fuzzing", f"runner crashed: {exc}")
                fuzz_res.status = "failed"
        tool_outputs["fuzzing"] = {
            "summary": fuzz_res.summary,
            "findings": fuzz_res.findings,
            "status": fuzz_res.status,
            "meta": fuzz_res.meta,
        }
        _finalize_toolrun(tr.id, fuzz_res)
        _record_fuzzer_toolruns(scan_id, target_id, fuzz_res)
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "fuzzing",
             "status": fuzz_res.status, "summary": fuzz_res.summary},
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

    value_context = ((tool_outputs.get("value-context") or {}).get("meta") or None)
    if value_context:
        for cand in candidates:
            cand.evidence.setdefault("value_context", value_context)

    sanity_suppressed = apply_candidate_sanity(
        ctx,
        candidates,
        enable_liveness=_toggle(toggles, "sanity_liveness", s.enable_sanity_liveness),
        enable_binding_gate=_toggle(toggles, "binding_hard_gate", s.enable_binding_hard_gate),
    )
    if sanity_suppressed:
        _log(scan_id, f"[{address}] sanity filter: suppressed {sanity_suppressed} obvious false-positive candidate(s)")

    knowledge_matches = 0
    for cand in candidates:
        knowledge_matches += len(annotate_candidate(cand))
    if knowledge_matches:
        _log(scan_id, f"[{address}] audit knowledge: attached {knowledge_matches} historical match(es)")

    # Cross-signal corroboration: mark findings that >=2 independent detectors /
    # the reasoner flagged on the same function (scoring then bumps confidence).
    mark_corroboration(candidates)
    # Collapse cross-file duplicates (same finding from proxy+impl+flattened) so a
    # report is readable. Runs AFTER corroboration so it sees every copy.
    before_dedup = len(candidates)
    candidates = dedup.collapse_duplicates(candidates)
    if len(candidates) < before_dedup:
        _log(scan_id, f"[{address}] dedup: {before_dedup} -> {len(candidates)} findings")

    if _toggle(toggles, "fuzzing", s.enable_fuzzing):
        tr = _create_toolrun(target_id, "fuzz-invariants")
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "fuzz-invariants", "status": "running"},
        )
        try:
            _log(scan_id, f"[{address}] fuzzing: detector-focused invariant generation")
            invariant_res = await asyncio.to_thread(
                fuzzing.run_detector_invariant_generation,
                ctx,
                candidates,
                workspace["fuzz"] / "detector_invariants",
                timeout=s.fuzz_timeout,
            )
        except Exception as exc:
            logger.warning("detector invariant generation failed on %s: %s", address, exc)
            invariant_res = _skip_runner("fuzz-invariants", f"runner crashed: {exc}")
            invariant_res.status = "failed"
        tool_outputs["fuzz-invariants"] = {
            "summary": invariant_res.summary,
            "findings": invariant_res.findings,
            "status": invariant_res.status,
            "meta": invariant_res.meta,
        }
        _finalize_toolrun(tr.id, invariant_res)
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": "fuzz-invariants",
             "status": invariant_res.status, "summary": invariant_res.summary},
        )

    # --- Score + (optional) refute + fork PoC + AI review + persist ------- #
    _set_target_status(scan_id, target_id, TargetStatus.AI)
    deepseek_on = _toggle(toggles, "deepseek", s.enable_deepseek)
    foundry_on = _toggle(toggles, "foundry", s.enable_foundry)
    poc_capable = (
        foundry_on and onchain.available and bool(s.rpc_url) and which("forge") is not None
    )
    MAX_POCS_PER_TARGET = max(0, int(s.max_pocs_per_target))
    poc_count = 0
    flashsim_on = (
        poc_capable
        and _toggle(toggles, "flashloan_sim", s.enable_flashloan_sim)
    )
    sim_count = 0

    refute_on = _toggle(toggles, "refutation", s.enable_refutation)
    candidates = sorted(candidates, key=_candidate_priority, reverse=True)
    for i, cand in enumerate(candidates):
        if mgr.is_cancelled(scan_id):
            break

        # FP-learning (dedup): a candidate matching a user-marked false-positive
        # fingerprint is suppressed and skips every expensive step below.
        suppressed = bool((cand.evidence or {}).get("suppressed"))
        known_suppressed = dedup.apply_suppression(cand, address)
        suppressed = suppressed or known_suppressed
        if suppressed:
            reason = (cand.evidence or {}).get("suppressed_reason") or "known false-positive"
            _log(scan_id, f"[{address}] suppressed: {cand.title[:70]} ({reason[:120]})")

        # Adversarial refutation (gap #3): an independent skeptic reads the code
        # and tries to DISPROVE the finding before it is scored. Skip pure-info
        # notes and weak candidates to save tokens.
        if refute_on and not suppressed and not (cand.evidence or {}).get("informational") and cand.impact_score >= 5:
            try:
                await asyncio.to_thread(refute_finding, ctx, cand)
                if (cand.evidence or {}).get("refuted"):
                    _log(scan_id, f"[{address}] refuted: {cand.title[:80]}")
                    if _toggle(toggles, "pattern_priors", s.enable_pattern_priors) and (cand.evidence or {}).get("refuted_concrete"):
                        reason = str(((cand.evidence or {}).get("refutation") or {}).get("refutation", ""))
                        dedup.record_pattern_refutation(cand, reason=reason)
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


def _combine_abis(*abis):
    """Merge proxy + implementation ABI entries for reachability checks."""
    out = []
    seen = set()
    for abi in abis:
        if isinstance(abi, dict):
            abi = abi.get("abi")
        if not isinstance(abi, list):
            continue
        for item in abi:
            if not isinstance(item, dict):
                continue
            key = (
                item.get("type"),
                item.get("name"),
                tuple((inp or {}).get("type") for inp in (item.get("inputs") or [])),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out or None


def _pick_main_source(
    source_dir: Path,
    contract_name: str | None,
    *,
    prefer_implementation: bool = False,
) -> Path | None:
    all_sols = list(source_dir.rglob("*.sol"))
    if prefer_implementation:
        sols = [p for p in all_sols if "_implementation" in p.parts] or all_sols
    else:
        sols = [p for p in all_sols if "_implementation" not in p.parts] or all_sols
    if not sols:
        return None
    if contract_name:
        for p in sols:
            if p.stem == contract_name:
                return p
    # Fallback: the largest file (usually the main contract).
    return max(sols, key=lambda p: p.stat().st_size if p.exists() else 0)


async def _run_tool(
    scan_id, target_id, tool, tool_outputs, workspace, have_source, main_source,
    bytecode, solc_version, evm_version=None, optimizer_enabled=None, optimizer_runs=None,
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
                    main_source=main_source,
                    solc_version=solc_version,
                    evm_version=evm_version,
                    optimizer_enabled=optimizer_enabled,
                    optimizer_runs=optimizer_runs,
                    timeout=s.slither_timeout,
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


def _taint_summary(report) -> dict:
    flows = list(getattr(report, "flows", []) or [])
    sink_counts: dict[str, int] = defaultdict(int)
    source_counts: dict[str, int] = defaultdict(int)
    top_flows = []
    high_confidence = 0
    cross_function = 0

    for flow in flows:
        sink_kind = str(getattr(flow, "sink_kind", "unknown") or "unknown")
        source_kind = str(getattr(flow, "source_kind", "unknown") or "unknown")
        sink_counts[sink_kind] += 1
        source_counts[source_kind] += 1
        confidence = float(getattr(flow, "confidence", 0.0) or 0.0)
        if confidence >= 0.75:
            high_confidence += 1
        if bool(getattr(flow, "cross_function", False)):
            cross_function += 1
        if len(top_flows) < 12:
            top_flows.append({
                "entrypoint": getattr(flow, "entrypoint", ""),
                "function": getattr(flow, "function", ""),
                "source": getattr(flow, "source", ""),
                "source_kind": source_kind,
                "sink": getattr(flow, "sink", ""),
                "sink_kind": sink_kind,
                "confidence": round(confidence, 3),
                "cross_function": bool(getattr(flow, "cross_function", False)),
            })

    return {
        "flow_count": len(flows),
        "sink_kinds": dict(sorted(sink_counts.items())),
        "source_kinds": dict(sorted(source_counts.items())),
        "high_confidence": high_confidence,
        "cross_function": cross_function,
        "top_flows": top_flows,
    }


def _candidate_priority(cand) -> float:
    evidence = cand.evidence or {}
    severity_bonus = {
        "critical": 18.0,
        "high": 12.0,
        "medium": 6.0,
        "low": 1.0,
        "info": 0.0,
    }.get(str(cand.severity_candidate or "").lower(), 0.0)

    score = float(cand.impact_score or 0.0) * 10.0
    score += float(cand.confidence_score or 0.0) * 4.0
    score += severity_bonus

    if evidence.get("corroborated"):
        score += 12.0 + min(6.0, len(evidence.get("corroborated_by") or []))
    if evidence.get("unprivileged") or evidence.get("attacker_controlled") or evidence.get("user_controlled_target_or_data"):
        score += 8.0
    if evidence.get("value_movement") or evidence.get("attacker_destination_control"):
        score += 6.0
    if evidence.get("economic_leverage") or evidence.get("exploit_class"):
        score += 4.0

    score += min(6.0, len(cand.next_tests or []) * 1.5)
    score += min(4.0, len(cand.affected_functions or []))

    if evidence.get("suppressed") or evidence.get("refuted"):
        score -= 40.0
    if evidence.get("informational"):
        score -= 20.0

    return score


def _skip_runner(tool: str, reason: str):
    from ..runners.base import RunnerResult

    return RunnerResult.skipped(tool, reason)



def _record_fuzzer_toolruns(scan_id: int, target_id: int, fuzz_res) -> None:
    """Expose Echidna/Medusa as visible ToolRuns even when generated by fuzzing."""
    from ..runners.base import RunnerResult

    meta = fuzz_res.meta or {}
    artifacts = meta.get("generated_fuzzer_artifacts") or {}
    versions = meta.get("tool_versions") or {}
    specs = (
        ("echidna", "existing_echidna", "echidna_config", "echidna . --config echidna.yaml --contract BulkAuditEchidnaProperties"),
        ("medusa", "existing_medusa", "medusa_config", "medusa fuzz --config medusa.json --no-color"),
    )
    for tool_name, existing_key, artifact_key, generated_command in specs:
        existing = meta.get(existing_key) or {}
        version_info = versions.get(tool_name) or {}
        installed = bool(version_info.get("installed")) or bool(which(tool_name))
        if tool_name == "echidna":
            installed = installed or bool(which("echidna-test"))
        status = existing.get("status") or "skipped"
        summary = existing.get("summary") or ""
        command = existing.get("command") or ""
        stdout_path = existing.get("stdout_path")
        stderr_path = existing.get("stderr_path")

        if not installed:
            status = "skipped"
            summary = f"{tool_name} not installed"
        elif status == "skipped" and artifacts.get(artifact_key):
            status = "ok"
            command = generated_command
            summary = f"generated {tool_name} starter config: {artifacts[artifact_key]}"
        elif status == "skipped" and fuzz_res.summary:
            summary = f"fuzzing skipped: {fuzz_res.summary}"
        elif not summary:
            summary = f"{tool_name} {status}"

        tr = _create_toolrun(target_id, tool_name)
        res = RunnerResult(
            tool_name=tool_name,
            status=status,
            command=command,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            summary=summary,
        )
        _finalize_toolrun(tr.id, res)
        hub.publish(
            scan_id,
            {"type": "tool_update", "target_id": target_id, "tool": tool_name, "status": status, "summary": summary},
        )

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
