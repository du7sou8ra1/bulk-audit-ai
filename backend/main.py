"""BulkAuditAI — FastAPI app + CLI.

Run the server:      python -m backend.main            (or: uvicorn backend.main:app)
Bulk scan a file:    python -m backend.main scan --addresses addresses.txt --profile standard
Scan one address:    python -m backend.main scan-one 0x...
Export a scan:       python -m backend.main export --scan-id 1 --format zip
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import ROOT_DIR, get_settings
from .database import SessionLocal, init_db


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if (
                exc.status_code == 404
                and scope["method"] in {"GET", "HEAD"}
                and not path.startswith(("api/", "ws/"))
            ):
                return await super().get_response("index.html", scope)
            raise


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    # Capture the running loop FIRST so sync endpoints AND recovery can schedule
    # scans onto it — fixes "no running event loop" on POST /api/scans.
    from .core.scanner import manager
    manager.set_loop(asyncio.get_running_loop())
    _recover_interrupted_scans()
    # Start the "before-drain" monitor if enabled (watches upgrades/codehash changes).
    if get_settings().enable_monitor:
        from .core.monitor import monitor
        monitor.start()
    yield
    try:
        from .core.monitor import monitor
        monitor.stop()
    except Exception:  # pragma: no cover - defensive
        pass


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="BulkAuditAI",
        version="0.1.0",
        description="Defensive bug-bounty triage",
        lifespan=_lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from .api import findings, scans, settings as settings_api, targets, watch, websocket

    app.include_router(scans.router)
    app.include_router(targets.router)
    app.include_router(findings.router)
    app.include_router(settings_api.router)
    app.include_router(watch.router)
    app.include_router(websocket.router)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "app": "BulkAuditAI", "version": "0.1.0"}

    # Serve the built frontend if present (single-port VPS deploy).
    dist = ROOT_DIR / "frontend" / "dist"
    if dist.exists():
        app.mount("/", SPAStaticFiles(directory=str(dist), html=True), name="frontend")

    return app


def _recover_interrupted_scans() -> None:
    """Mark scans left RUNNING by a previous process as failed, and RE-START any
    scan still QUEUED (e.g. created when an earlier error blocked its launch), so
    orphaned scans self-heal instead of sitting queued forever."""
    from sqlalchemy import select

    from .core.scanner import manager
    from .models import Scan, ScanStatus, utcnow

    with SessionLocal() as db:
        stuck = db.scalars(select(Scan).where(Scan.status == ScanStatus.RUNNING)).all()
        for s in stuck:
            s.status = ScanStatus.FAILED
            s.error = "interrupted by server restart"
            s.finished_at = utcnow()
        if stuck:
            db.commit()
        queued = [
            s.id for s in db.scalars(select(Scan).where(Scan.status == ScanStatus.QUEUED)).all()
        ]
    for scan_id in queued:
        manager.start_scan(scan_id)


app = create_app()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _cli_scan(addresses: list[str], name: str, profile: str, chain: str) -> int:
    from .core.scanner import manager, run_scan_pipeline
    from .models import Scan, ScanStatus, Target

    init_db()
    addresses = [a.strip() for a in addresses if a.strip()]
    if not addresses:
        print("no addresses provided", file=sys.stderr)
        return 2

    with SessionLocal() as db:
        scan = Scan(
            name=name or f"cli scan {len(addresses)} targets",
            chain=chain,
            scan_profile=profile,
            total_targets=len(addresses),
            status=ScanStatus.QUEUED,
            toggles={},
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
        for a in addresses:
            db.add(Target(scan_id=scan_id, address=a, chain=chain))
        db.commit()

    print(f"running scan #{scan_id} over {len(addresses)} target(s), profile={profile} ...")
    asyncio.run(run_scan_pipeline(scan_id, manager))

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        print(
            f"scan #{scan_id} {scan.status}: "
            f"critical={scan.critical_count} needs_investigation={scan.needs_investigation_count} "
            f"low_info={scan.low_info_count} false_positive={scan.false_positive_count}"
        )
    return 0


def _cli_export(scan_id: int, fmt: str, out: str | None) -> int:
    from .core import exporter
    from .models import Scan

    init_db()
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            print(f"scan {scan_id} not found", file=sys.stderr)
            return 2
        fn, _media, ext = exporter.EXPORTERS[fmt]
        data = fn(db, scan)
    out_path = Path(out) if out else Path(f"scan_{scan_id}.{ext}")
    out_path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    print(f"wrote {out_path}")
    return 0


def _cli_benchmark_exploits(
    *,
    scan_ids: list[int],
    case_ids: list[str],
    profile: str,
    run: bool,
    list_cases: bool,
    out: str | None,
) -> int:
    from .core import exploit_benchmark

    if list_cases:
        print(json.dumps({"cases": exploit_benchmark.list_benchmark_cases()}, indent=2, sort_keys=True))
        return 0

    try:
        cases = exploit_benchmark.select_benchmark_cases(case_ids)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    init_db()
    ids = list(scan_ids)
    if run:
        print(f"running exploit benchmark over {len(cases)} case(s), profile={profile} ...")
        ids += exploit_benchmark.run_benchmark_scans_sync(cases, profile=profile)
    if not ids:
        print("provide --scan-id or --run", file=sys.stderr)
        return 2

    with SessionLocal() as db:
        report = exploit_benchmark.validate_benchmark_scans(db, ids, cases=cases, profile=profile)
    if out:
        exploit_benchmark.write_report(report, Path(out))
        print(f"wrote {out}")

    print(
        f"benchmark {report.suite}: "
        f"{report.passed_cases}/{report.total_cases} passed over scan(s) {', '.join(map(str, report.scan_ids))}"
    )
    for result in report.results:
        status = "PASS" if result.passed else "FAIL"
        print(f"- {status} {result.case_id}: detectors={', '.join(result.present_detectors) or 'none'}")
        for error in result.errors:
            print(f"  * {error}")
    return 0 if report.passed else 1


def _cli_benchmark_detectors(
    *,
    case_ids: list[str],
    profile: str,
    list_cases: bool,
    out: str | None,
) -> int:
    from dataclasses import asdict

    from .core import exploit_benchmark

    if list_cases:
        print(json.dumps({"cases": exploit_benchmark.list_detector_regression_cases()}, indent=2, sort_keys=True))
        return 0

    try:
        cases = exploit_benchmark.select_detector_regression_cases(case_ids)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    results = exploit_benchmark.run_detector_regression_cases(cases, profile=profile)
    passed_cases = sum(1 for result in results if result.passed)
    report = {
        "suite": "detector-fixture-regression",
        "profile": profile,
        "passed": passed_cases == len(results),
        "total_cases": len(results),
        "passed_cases": passed_cases,
        "failed_cases": len(results) - passed_cases,
        "results": [asdict(result) for result in results],
    }
    if out:
        out_path = Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"wrote {out_path}")

    print(f"detector benchmark {passed_cases}/{len(results)} passed, profile={profile}")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"- {status} {result.case_id}: detectors={', '.join(result.present_detectors) or 'none'}")
        for missing in result.missing_detectors:
            print(f"  * missing detector: {missing}")
        for missing in result.missing_rule_ids:
            print(f"  * missing rule: {missing}")
        for error in result.detector_errors[:4]:
            print(f"  * detector error: {error}")
    return 0 if report["passed"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bulk-audit-ai")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="bulk scan addresses from a file or list")
    p_scan.add_argument("--addresses", help="path to a file with one address per line")
    p_scan.add_argument("--list", nargs="*", default=[], help="addresses passed inline")
    p_scan.add_argument("--name", default="")
    p_scan.add_argument("--profile", default="standard")
    p_scan.add_argument("--chain", default="ethereum")

    p_one = sub.add_parser("scan-one", help="scan a single address")
    p_one.add_argument("address")
    p_one.add_argument("--profile", default="standard")
    p_one.add_argument("--chain", default="ethereum")

    p_exp = sub.add_parser("export", help="export a scan")
    p_exp.add_argument("--scan-id", type=int, required=True)
    p_exp.add_argument("--format", default="json", choices=["json", "csv", "md", "markdown", "zip"])
    p_exp.add_argument("--out", default=None)

    p_bench = sub.add_parser("benchmark-exploits", help="Elite Phase 5 exploit regression benchmark")
    p_bench.add_argument("--scan-id", type=int, action="append", default=[], help="existing scan id to validate")
    p_bench.add_argument("--case", action="append", default=[], help="benchmark case id; repeatable")
    p_bench.add_argument("--profile", default="ultra-deep-v2")
    p_bench.add_argument("--run", action="store_true", help="run benchmark scans before validating")
    p_bench.add_argument("--list-cases", action="store_true", help="print benchmark case pack as JSON")
    p_bench.add_argument("--out", default=None, help="write JSON benchmark report")

    p_det = sub.add_parser("benchmark-detectors", help="run deterministic detector fixture regression benchmark")
    p_det.add_argument("--case", action="append", default=[], help="detector regression case id; repeatable")
    p_det.add_argument("--profile", default="ultra-deep-v2")
    p_det.add_argument("--list-cases", action="store_true", help="print detector fixture case pack as JSON")
    p_det.add_argument("--out", default=None, help="write JSON detector regression report")

    sub.add_parser("serve", help="run the web server (default)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        addrs: list[str] = list(args.list)
        if args.addresses:
            addrs += Path(args.addresses).read_text(encoding="utf-8").splitlines()
        return _cli_scan(addrs, args.name, args.profile, args.chain)
    if args.command == "scan-one":
        return _cli_scan([args.address], "", args.profile, args.chain)
    if args.command == "export":
        return _cli_export(args.scan_id, args.format, args.out)
    if args.command == "benchmark-exploits":
        return _cli_benchmark_exploits(
            scan_ids=args.scan_id,
            case_ids=args.case,
            profile=args.profile,
            run=args.run,
            list_cases=args.list_cases,
            out=args.out,
        )
    if args.command == "benchmark-detectors":
        return _cli_benchmark_detectors(
            case_ids=args.case,
            profile=args.profile,
            list_cases=args.list_cases,
            out=args.out,
        )

    # default: serve
    import uvicorn

    s = get_settings()
    uvicorn.run("backend.main:app", host=s.host, port=s.port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
