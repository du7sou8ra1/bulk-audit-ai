"""BulkAuditAI — FastAPI app + CLI.

Run the server:      python -m backend.main            (or: uvicorn backend.main:app)
Bulk scan a file:    python -m backend.main scan --addresses addresses.txt --profile standard
Scan one address:    python -m backend.main scan-one 0x...
Export a scan:       python -m backend.main export --scan-id 1 --format zip
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import ROOT_DIR, get_settings
from .database import SessionLocal, init_db


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    _recover_interrupted_scans()
    yield


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

    from .api import findings, scans, settings as settings_api, targets, websocket

    app.include_router(scans.router)
    app.include_router(targets.router)
    app.include_router(findings.router)
    app.include_router(settings_api.router)
    app.include_router(websocket.router)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "app": "BulkAuditAI", "version": "0.1.0"}

    # Serve the built frontend if present (single-port VPS deploy).
    dist = ROOT_DIR / "frontend" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="frontend")

    return app


def _recover_interrupted_scans() -> None:
    """Mark scans left RUNNING by a previous process as failed (no zombie state)."""
    from .models import Scan, ScanStatus, utcnow

    with SessionLocal() as db:
        from sqlalchemy import select

        stuck = db.scalars(select(Scan).where(Scan.status == ScanStatus.RUNNING)).all()
        for s in stuck:
            s.status = ScanStatus.FAILED
            s.error = "interrupted by server restart"
            s.finished_at = utcnow()
        if stuck:
            db.commit()


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

    # default: serve
    import uvicorn

    s = get_settings()
    uvicorn.run("backend.main:app", host=s.host, port=s.port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
