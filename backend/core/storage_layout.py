"""Storage-layout hints for proxy/module/cross-contract validation.

This is not a Solidity compiler replacement. It builds conservative hints that
help the auditor reason about where state-changing bugs land: EIP-1967 proxy
slots, declared storage variables, mappings, owner/admin/initializer slots,
delegatecall/module storage-sharing, and functions that read/write those slots.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..detectors.base import TargetContext, strip_comments
from ..runners.base import RunnerResult
from .proxy_resolver import ADMIN_SLOT, BEACON_SLOT, IMPL_SLOT, LEGACY_IMPL_SLOT

TOOL_NAME = "storage-layout"
SCHEMA = "bulk-audit-storage-layout/v1"

_STATE_RE = re.compile(
    r"^\s*(?P<type>mapping\s*\([^;]+\)|[A-Za-z_]\w*(?:\s+payable)?(?:\[[^\]]*\])?|address\s+payable|uint\d*|int\d*|bytes\d*|bytes|string|bool)\s+"
    r"(?P<attrs>(?:(?:public|private|internal|constant|immutable|override)\s+)*)"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=|;)",
    re.MULTILINE,
)
_CONTRACT_MARKER_RE = re.compile(r"\b(function|modifier|event|error|struct|enum|contract|interface|library)\b")
_CRITICAL_VAR_RE = re.compile(
    r"owner|admin|govern|guardian|pauser|manager|operator|controller|comptroller|oracle|price|feed|"
    r"implementation|beacon|initialized|initializing|nonce|root|processed|claimed|nullifier|"
    r"balance|allowance|supply|shares|assets|reserve|pair|pool|router|strategy|verifier|bridge|messenger",
    re.I,
)
_AUTH_RE = re.compile(r"owner|admin|govern|guardian|pauser|manager|operator|role", re.I)
_INIT_RE = re.compile(r"initialized|initializing|initializer|version", re.I)
_ACCOUNTING_RE = re.compile(r"balance|allowance|supply|share|asset|reserve|debt|collateral|reward|accum", re.I)
_CROSS_RE = re.compile(r"oracle|price|feed|controller|comptroller|pair|pool|router|strategy|verifier|bridge|messenger", re.I)
_WRITE_RE = re.compile(r"(?<![=!<>])=(?!=)|\+=|-=|\+\+|--|\.push\s*\(|delete\s+")


def run_storage_layout(ctx: TargetContext, out_dir: Path) -> RunnerResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    layout = build_storage_layout(ctx)
    json_path = out_dir / "storage_layout.json"
    md_path = out_dir / "storage_layout.md"
    json_path.write_text(json.dumps(layout, indent=2, sort_keys=True, default=str), encoding="utf-8")
    md_path.write_text(render_storage_layout_markdown(layout), encoding="utf-8")
    summary = layout.get("summary") or {}
    text = (
        f"storage layout: {summary.get('declared_slot_count', 0)} declared slot hint(s), "
        f"{summary.get('critical_slot_count', 0)} critical slot hint(s), "
        f"{summary.get('module_context_count', 0)} module/proxy context hint(s)"
    )
    return RunnerResult(
        tool_name=TOOL_NAME,
        status="ok",
        json_output_path=str(json_path),
        stdout_path=str(md_path),
        summary=text,
        findings=[],
        meta=layout,
    )


def build_storage_layout(ctx: TargetContext) -> dict[str, Any]:
    declarations = _declared_state_vars(ctx.source_files or {})
    semantic = getattr(ctx, "semantic", None)
    rw = _read_write_matrix(semantic)
    slot_hints = _assign_slot_hints(declarations, rw)
    proxy_slots = _proxy_slot_hints(ctx)
    module_context = _module_context(ctx, declarations, semantic)
    critical_slots = _critical_slot_hints(slot_hints, rw)
    samples = _sample_storage(ctx, slot_hints, proxy_slots)
    collision_hints = _collision_hints(declarations)
    graph_links = _graph_storage_links(ctx)

    by_family = defaultdict(int)
    for row in critical_slots:
        by_family[str(row.get("family") or "other")] += 1

    layout = {
        "schema": SCHEMA,
        "target": {
            "address": ctx.address,
            "chain": ctx.chain,
            "contract_name": ctx.contract_name,
            "is_proxy": bool(getattr(ctx.proxy_info, "is_proxy", False)) if ctx.proxy_info else False,
            "proxy_type": getattr(ctx.proxy_info, "proxy_type", None) if ctx.proxy_info else None,
            "implementation": getattr(ctx.proxy_info, "implementation", None) if ctx.proxy_info else None,
        },
        "proxy_slots": proxy_slots,
        "declared_slots": slot_hints,
        "critical_slots": critical_slots,
        "read_write_matrix": rw,
        "module_context": module_context,
        "collision_hints": collision_hints,
        "protocol_graph_links": graph_links,
        "storage_samples": samples,
        "summary": {
            "declared_slot_count": len(slot_hints),
            "critical_slot_count": len(critical_slots),
            "module_context_count": len(module_context),
            "sample_count": len(samples),
            "critical_families": dict(sorted(by_family.items())),
            "has_proxy_storage": bool(proxy_slots),
            "has_delegatecall_or_modules": any(row.get("kind") in {"delegatecall", "module_source", "proxy_storage"} for row in module_context),
        },
    }
    return layout


def render_storage_layout_markdown(layout: dict[str, Any]) -> str:
    target = layout.get("target") or {}
    lines = [
        "# Storage Layout Hints",
        "",
        f"Target: `{target.get('contract_name') or target.get('address') or 'unknown'}`",
        f"Chain: `{target.get('chain') or 'unknown'}`",
        "",
        "## Critical Slots",
    ]
    crit = layout.get("critical_slots") or []
    if crit:
        for row in crit[:40]:
            slot = row.get("slot") if row.get("slot") is not None else row.get("slot_hex")
            lines.append(f"- `{row.get('family')}` `{row.get('name')}` slot `{slot}` ({row.get('source_group')})")
    else:
        lines.append("- none inferred")
    lines.extend(["", "## Proxy Slots"])
    for row in layout.get("proxy_slots") or []:
        lines.append(f"- `{row.get('name')}` `{row.get('slot_hex')}` value `{row.get('value') or 'unknown'}`")
    if not layout.get("proxy_slots"):
        lines.append("- none")
    lines.extend(["", "## Module / Storage-Sharing Context"])
    for row in layout.get("module_context") or []:
        lines.append(f"- `{row.get('kind')}`: {row.get('detail')}")
    if not layout.get("module_context"):
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def compact_storage_context(layout: dict[str, Any] | None, *, max_rows: int = 16) -> dict[str, Any]:
    if not layout:
        return {}
    return {
        "summary": layout.get("summary") or {},
        "proxy_slots": (layout.get("proxy_slots") or [])[:8],
        "critical_slots": (layout.get("critical_slots") or [])[:max_rows],
        "module_context": (layout.get("module_context") or [])[:8],
        "collision_hints": (layout.get("collision_hints") or [])[:8],
        "protocol_graph_links": (layout.get("protocol_graph_links") or [])[:8],
    }


def _declared_state_vars(source_files: dict[str, str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path, raw in sorted((source_files or {}).items()):
        if not raw:
            continue
        src = _contract_level_source(strip_comments(raw))
        for m in _STATE_RE.finditer(src):
            line_text = src[m.start() : src.find("\n", m.start()) if src.find("\n", m.start()) != -1 else len(src)]
            if _CONTRACT_MARKER_RE.search(line_text):
                continue
            attrs = (m.group("attrs") or "").split()
            out.append({
                "name": m.group("name"),
                "type": re.sub(r"\s+", " ", m.group("type").strip()),
                "attrs": attrs,
                "file": path,
                "line": _line_of(src, m.start()),
                "source_group": _source_group(path),
                "is_mapping": m.group("type").strip().startswith("mapping"),
                "is_constant_like": bool(set(attrs) & {"constant", "immutable"}),
            })
    return out


def _assign_slot_hints(declarations: list[dict[str, Any]], rw: dict[str, Any]) -> list[dict[str, Any]]:
    slots_by_group: dict[str, int] = defaultdict(int)
    out: list[dict[str, Any]] = []
    for decl in declarations:
        row = dict(decl)
        if row.get("is_constant_like"):
            row["slot"] = None
            row["slot_note"] = "constant/immutable: no normal storage slot"
        else:
            group = str(row.get("source_group") or "target")
            slot = slots_by_group[group]
            slots_by_group[group] += 1
            row["slot"] = slot
            row["slot_hex"] = hex(slot)
            row["slot_note"] = "approximate declaration-order slot; use compiler storageLayout for exact packing"
        name = str(row.get("name") or "")
        matrix = rw.get(name) or {}
        row["read_by"] = matrix.get("read_by", [])[:12]
        row["written_by"] = matrix.get("written_by", [])[:12]
        row["family"] = _critical_family(name, str(row.get("type") or ""))
        out.append(row)
    return out


def _read_write_matrix(semantic) -> dict[str, Any]:
    if not semantic:
        return {}
    out: dict[str, dict[str, set[str]]] = {}
    for name in sorted((semantic.state_vars or {}).keys() | (semantic.mappings or {}).keys()):
        out.setdefault(name, {"read_by": set(), "written_by": set(), "entrypoint_writers": set()})
    for fn in semantic.functions_by_key.values():
        for name in fn.reads or set():
            if name in out:
                out[name]["read_by"].add(fn.name)
        for name in fn.writes or set():
            if name in out:
                out[name]["written_by"].add(fn.name)
                if getattr(fn, "is_entrypoint", False):
                    out[name]["entrypoint_writers"].add(fn.name)
    return {name: {k: sorted(v) for k, v in row.items()} for name, row in out.items()}


def _proxy_slot_hints(ctx: TargetContext) -> list[dict[str, Any]]:
    proxy = ctx.proxy_info
    if not proxy:
        return []
    slot_reads = (getattr(proxy, "evidence", None) or {}).get("slot_reads") or {}
    rows = [
        {"name": "eip1967.implementation", "slot": IMPL_SLOT, "slot_hex": hex(IMPL_SLOT), "value": getattr(proxy, "implementation", None) or slot_reads.get("implementation_value")},
        {"name": "eip1967.admin", "slot": ADMIN_SLOT, "slot_hex": hex(ADMIN_SLOT), "value": getattr(proxy, "admin", None) or slot_reads.get("admin_value")},
        {"name": "eip1967.beacon", "slot": BEACON_SLOT, "slot_hex": hex(BEACON_SLOT), "value": getattr(proxy, "beacon", None) or slot_reads.get("beacon_value")},
        {"name": "legacy.zeppelinos.implementation", "slot": LEGACY_IMPL_SLOT, "slot_hex": hex(LEGACY_IMPL_SLOT), "value": slot_reads.get("legacy_impl_value")},
    ]
    return [row for row in rows if row.get("value") or bool(getattr(proxy, "is_proxy", False))]


def _critical_slot_hints(slot_hints: list[dict[str, Any]], rw: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in slot_hints:
        name = str(row.get("name") or "")
        type_name = str(row.get("type") or "")
        family = _critical_family(name, type_name)
        if not family:
            continue
        item = {
            "name": name,
            "type": type_name,
            "family": family,
            "slot": row.get("slot"),
            "slot_hex": row.get("slot_hex"),
            "file": row.get("file"),
            "line": row.get("line"),
            "source_group": row.get("source_group"),
            "read_by": row.get("read_by") or [],
            "written_by": row.get("written_by") or [],
            "entrypoint_writers": (rw.get(name) or {}).get("entrypoint_writers", []),
            "risk": _risk_for_family(family, bool((rw.get(name) or {}).get("entrypoint_writers"))),
        }
        out.append(item)
    out.sort(key=lambda r: (_family_priority(str(r.get("family"))), str(r.get("source_group")), int(r.get("slot") or 10**9), str(r.get("name"))))
    return out


def _module_context(ctx: TargetContext, declarations: list[dict[str, Any]], semantic) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    proxy = ctx.proxy_info
    if proxy and getattr(proxy, "is_proxy", False):
        rows.append({
            "kind": "proxy_storage",
            "detail": "implementation code executes against proxy storage; validate critical slot writes on the proxy address",
            "implementation": getattr(proxy, "implementation", None),
            "proxy_type": getattr(proxy, "proxy_type", None),
        })
    module_files = sorted({d.get("file") for d in declarations if d.get("source_group") == "module"})
    for file in module_files[:12]:
        rows.append({"kind": "module_source", "detail": f"module/facet source included: {file}", "file": file})
    if semantic:
        for fn in semantic.functions_by_key.values():
            body = fn.body or ""
            if "delegatecall" in body:
                rows.append({
                    "kind": "delegatecall",
                    "detail": f"{fn.name} contains delegatecall; target code can mutate caller storage",
                    "function": fn.name,
                    "file": fn.file,
                    "line": fn.line,
                    "writes": sorted(fn.writes or [])[:12],
                    "entrypoint": bool(getattr(fn, "is_entrypoint", False)),
                })
    return rows


def _sample_storage(ctx: TargetContext, slot_hints: list[dict[str, Any]], proxy_slots: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    onchain = getattr(ctx, "onchain", None)
    if not onchain or not getattr(onchain, "available", False):
        return []
    slots: list[tuple[str, int | str]] = []
    for row in proxy_slots:
        if row.get("slot") is not None:
            slots.append((str(row.get("name")), row["slot"]))
    for row in slot_hints:
        if row.get("slot") is not None and (row.get("family") or row.get("slot", 999) < 8):
            slots.append((str(row.get("name")), int(row["slot"])))
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, slot in slots:
        key = str(slot)
        if key in seen or len(out) >= limit:
            continue
        seen.add(key)
        try:
            value = onchain.get_storage_at(ctx.address, slot)
        except Exception:
            value = None
        out.append({"name": name, "slot": slot, "slot_hex": hex(slot) if isinstance(slot, int) else str(slot), "value": value})
    return out


def _collision_hints(declarations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for decl in declarations:
        by_name[str(decl.get("name") or "")].append(decl)
    out = []
    for name, rows in sorted(by_name.items()):
        groups = sorted({str(r.get("source_group") or "target") for r in rows})
        if len(rows) > 1 and len(groups) > 1:
            out.append({
                "name": name,
                "groups": groups,
                "locations": [{"file": r.get("file"), "line": r.get("line"), "type": r.get("type")} for r in rows[:8]],
                "risk": "same state variable name appears across target/implementation/module sources; verify storage layout compatibility",
            })
    return out


def _graph_storage_links(ctx: TargetContext) -> list[dict[str, Any]]:
    graph = getattr(ctx, "protocol_graph", None) or {}
    rows = []
    for node in graph.get("nodes") or []:
        role = str(node.get("role") or "")
        if role in {"oracle", "lending_controller", "lending_market", "erc4626_vault", "amm_pair", "strategy", "verifier", "bridge_messenger"}:
            rows.append({
                "role": role,
                "label": node.get("label"),
                "address": node.get("address"),
                "source": node.get("source"),
                "state_link": "stored reference or typed call target that may control cross-contract accounting",
            })
    return rows[:24]


def _critical_family(name: str, type_name: str) -> str | None:
    hay = f"{name} {type_name}"
    if not _CRITICAL_VAR_RE.search(hay):
        return None
    if _AUTH_RE.search(hay):
        return "authority"
    if _INIT_RE.search(hay):
        return "initializer"
    if _ACCOUNTING_RE.search(hay):
        return "accounting"
    if _CROSS_RE.search(hay):
        return "cross_contract"
    return "critical"


def _risk_for_family(family: str, has_entrypoint_writer: bool) -> str:
    base = {
        "authority": "privilege slot controls upgrades/pauses/roles",
        "initializer": "initializer/version slot can gate takeover or reinitialization",
        "accounting": "accounting slot affects value conservation and solvency",
        "cross_contract": "stored dependency can redirect oracle/market/vault/bridge behavior",
    }.get(family, "critical storage slot")
    if has_entrypoint_writer:
        return base + "; externally reachable writer observed"
    return base


def _family_priority(family: str) -> int:
    return {"authority": 0, "initializer": 1, "cross_contract": 2, "accounting": 3}.get(family, 9)


def _source_group(path: str) -> str:
    low = (path or "").replace("\\", "/").lower()
    if "/_modules/" in f"/{low}" or low.startswith("_modules/"):
        return "module"
    if "/_implementation/" in f"/{low}" or low.startswith("_implementation/"):
        return "implementation"
    return "target"


def _contract_level_source(src: str) -> str:
    out: list[str] = []
    depth = 0
    for ch in src:
        keep = depth <= 1 or ch == "\n"
        out.append(ch if keep else ("\n" if ch == "\n" else " "))
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    return "".join(out)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1
