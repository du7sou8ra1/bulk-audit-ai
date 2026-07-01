"""Protocol graph extraction for cross-contract economic reasoning.

The scanner usually starts with one address, but real DeFi bugs often live in the
relationships between an oracle, controller, market token, vault wrapper, AMM
pair, router, verifier, or bridge messenger. This module builds a conservative
role graph from source/ABI/semantic facts plus safe read-only address getters.

It is intentionally heuristic. The graph is recon context and detector evidence,
not a proof that every companion contract has been scanned.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ..detectors.base import TargetContext
from ..runners.base import RunnerResult

TOOL_NAME = "protocol-graph"
SCHEMA = "bulk-audit-protocol-graph/v1"

_ROLE_RULES: tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...] = (
    ("oracle", re.compile(r"oracle|price(feed)?|aggregator|chainlink|pyth|redstone|twap|anchored|validatorproxy", re.I), ("uses_oracle", "reads_price")),
    ("lending_controller", re.compile(r"comptroller|unitroller|lendingpool|pooldata|controller|riskmanager|markets?", re.I), ("uses_lending_controller", "checks_liquidity")),
    ("lending_market", re.compile(r"\b(c|v|a|d)token\b|ctoken|vtoken|atoken|debttoken|market|borrowable|collateral", re.I), ("uses_lending_market", "moves_debt")),
    ("erc4626_vault", re.compile(r"erc4626|vault|wrapper|wrapped|share|shares", re.I), ("uses_vault", "reads_exchange_rate")),
    ("amm_pair", re.compile(r"uniswap|pancake|sushiswap|camelot|curve|balancer|pair|amm|pool|lp", re.I), ("uses_amm", "syncs_reserves")),
    ("router", re.compile(r"router|swaprouter|quoter|aggregator|executor", re.I), ("uses_router", "routes_calls")),
    ("asset", re.compile(r"asset|underlying|collateral|borrowasset|debtasset|token0|token1|token|reward|stable|weth|usdc|dai", re.I), ("uses_asset", "moves_asset")),
    ("bridge_messenger", re.compile(r"bridge|messenger|endpoint|inbox|outbox|relayer|receiver|gateway|mailbox|layerzero|ccip", re.I), ("uses_bridge", "relays_message")),
    ("verifier", re.compile(r"verifier|verify|proof|groth|plonk|snark|validator", re.I), ("uses_verifier", "verifies_proof")),
    ("authority", re.compile(r"owner|admin|governor|governance|guardian|pauser|timelock|multisig|manager", re.I), ("controlled_by", "guards")),
    ("strategy", re.compile(r"strategy|adapter|module|facet|implementation|beacon|logic", re.I), ("uses_strategy", "delegates_to")),
    ("hook", re.compile(r"hook|callback|receiver|onerc|flashloan|flash", re.I), ("uses_hook", "callback")),
)

_HIGH_VALUE_ROLES = {
    "oracle",
    "lending_controller",
    "lending_market",
    "erc4626_vault",
    "amm_pair",
    "router",
    "bridge_messenger",
    "verifier",
    "strategy",
}

_TYPED_CALL_RE = re.compile(r"\b(?P<target>[A-Za-z_]\w*)\s*\.\s*(?P<method>[A-Za-z_]\w*)\s*\(")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SKIP_TARGETS = {"msg", "tx", "block", "super", "this", "address", "abi", "type", "console", "assert", "require"}


def run_protocol_graph(ctx: TargetContext, out_dir: Path) -> RunnerResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    graph = build_protocol_graph(ctx)
    graph_path = out_dir / "protocol_graph.json"
    graph_path.write_text(json.dumps(graph, indent=2, sort_keys=True, default=str), encoding="utf-8")
    md_path = out_dir / "protocol_graph.md"
    md_path.write_text(render_protocol_graph_markdown(graph), encoding="utf-8")

    summary = graph.get("summary") or {}
    text = (
        f"protocol graph: {summary.get('node_count', 0)} node(s), "
        f"{summary.get('edge_count', 0)} edge(s), "
        f"{summary.get('surface_count', 0)} surface(s), "
        f"{summary.get('companion_candidate_count', 0)} companion candidate(s)"
    )
    return RunnerResult(
        tool_name=TOOL_NAME,
        status="ok",
        json_output_path=str(graph_path),
        stdout_path=str(md_path),
        summary=text,
        findings=[],
        meta=graph,
    )


def build_protocol_graph(ctx: TargetContext) -> dict[str, Any]:
    source_text = ctx.all_source_text() or ""
    semantic = getattr(ctx, "semantic", None)
    getter_addresses = _resolve_address_getters(ctx, semantic)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_by_var: dict[str, str] = {}
    node_ids: set[str] = set()

    def add_node(node: dict[str, Any]) -> str:
        node_id = str(node["id"])
        if node_id in node_ids:
            for existing in nodes:
                if existing["id"] == node_id:
                    if node.get("address") and not existing.get("address"):
                        existing["address"] = node["address"]
                    existing.setdefault("evidence", []).extend(node.get("evidence") or [])
                    existing["confidence"] = max(float(existing.get("confidence") or 0), float(node.get("confidence") or 0))
                    return node_id
        node_ids.add(node_id)
        node.setdefault("evidence", [])
        nodes.append(node)
        return node_id

    def add_edge(src: str, dst: str, kind: str, **extra: Any) -> None:
        if not src or not dst or src == dst:
            return
        key = (src, dst, kind, extra.get("function"), extra.get("method"))
        for edge in edges:
            if (edge.get("from"), edge.get("to"), edge.get("kind"), edge.get("function"), edge.get("method")) == key:
                return
        row = {"from": src, "to": dst, "kind": kind}
        row.update({k: v for k, v in extra.items() if v not in (None, "", [])})
        edges.append(row)

    target_id = add_node({
        "id": "target",
        "label": ctx.contract_name or ctx.address,
        "kind": "contract",
        "role": "target",
        "address": ctx.address,
        "source": "scan_target",
        "confidence": 1.0,
    })

    proxy = getattr(ctx, "proxy_info", None)
    if proxy:
        for role, addr in (
            ("implementation", getattr(proxy, "implementation", None)),
            ("proxy_admin", getattr(proxy, "admin", None)),
            ("proxy_admin_owner", getattr(proxy, "admin_owner", None)),
            ("owner", getattr(proxy, "owner", None)),
            ("beacon", getattr(proxy, "beacon", None)),
        ):
            if not addr:
                continue
            node_id = add_node({
                "id": f"proxy:{role}",
                "label": role,
                "kind": "contract_ref",
                "role": "authority" if "admin" in role or role == "owner" else "strategy",
                "address": addr,
                "source": "proxy_resolution",
                "confidence": 0.95,
                "evidence": [role],
            })
            add_edge(target_id, node_id, role)

    if semantic:
        for name, meta in sorted((semantic.state_vars or {}).items()):
            role, confidence = _infer_role(name, str(meta.get("type") or ""))
            if not role:
                continue
            address = getter_addresses.get(name)
            node_id = add_node({
                "id": f"state:{name}",
                "label": name,
                "kind": "contract_ref",
                "role": role,
                "type_name": meta.get("type"),
                "address": address,
                "source": "state_var",
                "file": meta.get("file"),
                "line": meta.get("line"),
                "confidence": confidence,
                "evidence": [f"state variable {name}: {meta.get('type') or 'unknown'}"],
            })
            node_by_var[name] = node_id
            add_edge(target_id, node_id, _edge_kind_for_role(role, "has_reference"), file=meta.get("file"), line=meta.get("line"))

        for fn in semantic.functions_by_key.values():
            body = fn.body or ""
            for state_name in sorted((fn.reads or set()) | (fn.writes or set())):
                dst = node_by_var.get(state_name)
                if not dst:
                    continue
                add_edge(
                    target_id,
                    dst,
                    "writes_reference" if state_name in (fn.writes or set()) else "reads_reference",
                    function=fn.name,
                    file=fn.file,
                    line=fn.line,
                )
            for m in _TYPED_CALL_RE.finditer(body):
                raw_target = m.group("target")
                method = m.group("method")
                if raw_target.lower() in _SKIP_TARGETS:
                    continue
                dst = node_by_var.get(raw_target)
                if not dst:
                    role, confidence = _infer_role(raw_target, "")
                    if not role:
                        continue
                    dst = add_node({
                        "id": f"calltarget:{raw_target}",
                        "label": raw_target,
                        "kind": "contract_ref",
                        "role": role,
                        "source": "typed_call_target",
                        "confidence": min(0.8, confidence),
                        "evidence": [f"{fn.name} calls {raw_target}.{method}()"],
                    })
                    node_by_var[raw_target] = dst
                add_edge(target_id, dst, _edge_kind_for_method(method), function=fn.name, method=method, file=fn.file, line=fn.line)

    for name in sorted(_abi_address_getters(ctx.abi)):
        if name in node_by_var:
            continue
        role, confidence = _infer_role(name, "address getter")
        if not role:
            continue
        node_id = add_node({
            "id": f"abi:{name}",
            "label": name,
            "kind": "contract_ref",
            "role": role,
            "address": getter_addresses.get(name),
            "source": "abi_getter",
            "confidence": max(0.6, confidence - 0.1),
            "evidence": [f"ABI address getter {name}()"],
        })
        node_by_var[name] = node_id
        add_edge(target_id, node_id, _edge_kind_for_role(role, "abi_reference"))

    surfaces = _infer_surfaces(nodes, edges, source_text)
    companion_candidates = _companion_candidates(nodes, ctx.address)
    groups = _build_groups(surfaces, nodes)
    role_counts = Counter(str(n.get("role") or "unknown") for n in nodes)

    graph = {
        "schema": SCHEMA,
        "target": {
            "address": ctx.address,
            "chain": ctx.chain,
            "contract_name": ctx.contract_name,
            "profile": ctx.profile,
        },
        "nodes": nodes,
        "edges": edges,
        "surfaces": surfaces,
        "groups": groups,
        "companion_scan_candidates": companion_candidates,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "surface_count": len(surfaces),
            "companion_candidate_count": len(companion_candidates),
            "roles": dict(sorted(role_counts.items())),
            "high_risk_surfaces": [s["id"] for s in surfaces if s.get("severity") in {"critical", "high"}],
        },
    }
    return graph


def build_scan_protocol_graph(scan_id: int, scan_dir: Path) -> dict[str, Any]:
    target_graphs: list[dict[str, Any]] = []
    if scan_dir.exists():
        for path in sorted(scan_dir.glob("0x*/protocol_graph.json")):
            try:
                target_graphs.append(json.loads(path.read_text(encoding="utf-8")))
            except Exception:
                continue

    target_addresses = {
        str((g.get("target") or {}).get("address") or "").lower()
        for g in target_graphs
        if (g.get("target") or {}).get("address")
    }
    surfaces: list[dict[str, Any]] = []
    candidates: dict[str, dict[str, Any]] = {}
    role_counts: Counter[str] = Counter()
    for graph in target_graphs:
        target = graph.get("target") or {}
        target_addr = target.get("address")
        target_name = target.get("contract_name") or target_addr
        role_counts.update((graph.get("summary") or {}).get("roles") or {})
        for surface in graph.get("surfaces") or []:
            row = dict(surface)
            row["target_address"] = target_addr
            row["target_label"] = target_name
            surfaces.append(row)
        for cand in graph.get("companion_scan_candidates") or []:
            key = str(cand.get("address") or f"{target_addr}:{cand.get('role')}:{cand.get('label')}").lower()
            existing = candidates.setdefault(key, {**cand, "observed_from": []})
            existing["observed_from"].append(target_addr)
            if cand.get("address") and str(cand.get("address")).lower() in target_addresses:
                existing["already_in_scan"] = True

    surfaces.sort(key=lambda row: (0 if row.get("severity") in {"critical", "high"} else 1, str(row.get("id"))))
    companion_rows = sorted(candidates.values(), key=lambda row: (not bool(row.get("address")), str(row.get("role")), str(row.get("label"))))
    graph = {
        "schema": "bulk-audit-scan-protocol-graph/v1",
        "scan_id": scan_id,
        "target_count": len(target_graphs),
        "surfaces": surfaces,
        "companion_scan_candidates": companion_rows,
        "summary": {
            "target_graph_count": len(target_graphs),
            "surface_count": len(surfaces),
            "companion_candidate_count": len(companion_rows),
            "already_scanned_companions": sum(1 for row in companion_rows if row.get("already_in_scan")),
            "roles": dict(sorted(role_counts.items())),
            "high_risk_surfaces": [s["id"] for s in surfaces if s.get("severity") in {"critical", "high"}],
        },
    }
    return graph


def write_scan_protocol_graph(scan_id: int, scan_dir: Path) -> dict[str, Any]:
    graph = build_scan_protocol_graph(scan_id, scan_dir)
    path = scan_dir / "protocol_graph.json"
    path.write_text(json.dumps(graph, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return graph


def render_protocol_graph_markdown(graph: dict[str, Any]) -> str:
    target = graph.get("target") or {}
    lines = [
        "# Protocol Graph",
        "",
        f"Target: `{target.get('contract_name') or target.get('address') or 'unknown'}`",
        f"Chain: `{target.get('chain') or 'unknown'}`",
        "",
        "## Surfaces",
    ]
    surfaces = graph.get("surfaces") or []
    if surfaces:
        for surface in surfaces:
            lines.append(f"- `{surface.get('id')}` ({surface.get('severity')}): {surface.get('title')}")
    else:
        lines.append("- none inferred")
    lines.extend(["", "## Components"])
    for node in graph.get("nodes") or []:
        role = node.get("role") or "unknown"
        addr = f" `{node.get('address')}`" if node.get("address") else ""
        lines.append(f"- `{role}` `{node.get('label')}`{addr} ({node.get('source')})")
    lines.extend(["", "## Companion Scan Candidates"])
    companions = graph.get("companion_scan_candidates") or []
    if companions:
        for cand in companions:
            addr = cand.get("address") or "unresolved"
            lines.append(f"- `{cand.get('role')}` `{cand.get('label')}`: {addr}")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def _resolve_address_getters(ctx: TargetContext, semantic, *, max_reads: int = 28) -> dict[str, str]:
    onchain = getattr(ctx, "onchain", None)
    if not onchain or not getattr(onchain, "available", False):
        return {}
    names: list[str] = []
    names.extend(sorted(_abi_address_getters(ctx.abi)))
    if semantic:
        for name, meta in sorted((semantic.state_vars or {}).items()):
            role, _confidence = _infer_role(name, str(meta.get("type") or ""))
            if role and _looks_like_contract_reference(str(meta.get("type") or "")):
                names.append(name)
    out: dict[str, str] = {}
    seen: set[str] = set()
    for name in names:
        if name in seen or len(out) >= max_reads:
            continue
        seen.add(name)
        try:
            value = onchain.call_typed(ctx.address, f"{name}()", return_types=["address"])
        except Exception:
            value = None
        if _valid_address(value):
            try:
                value = onchain.checksum(str(value))
            except Exception:
                value = str(value)
            out[name] = value
    return out


def _abi_items(abi: list | dict | None) -> list[dict[str, Any]]:
    items = abi.get("abi") if isinstance(abi, dict) else abi
    return [item for item in (items or []) if isinstance(item, dict)] if isinstance(items, list) else []


def _abi_address_getters(abi: list | dict | None) -> set[str]:
    names: set[str] = set()
    for item in _abi_items(abi):
        if item.get("type") != "function" or item.get("inputs"):
            continue
        outputs = item.get("outputs") or []
        if len(outputs) == 1 and isinstance(outputs[0], dict) and outputs[0].get("type") == "address":
            name = str(item.get("name") or "")
            if name:
                names.add(name)
    return names


def _valid_address(value: Any) -> bool:
    try:
        text = str(value)
        return bool(_ADDRESS_RE.match(text)) and int(text, 16) != 0
    except Exception:
        return False


def _looks_like_contract_reference(type_name: str) -> bool:
    t = type_name.strip()
    if not t:
        return False
    if t.startswith("mapping"):
        return False
    if t in {"address", "address payable"}:
        return True
    if re.match(r"^(I[A-Z]|[A-Z])", t):
        return True
    return bool(re.search(r"contract|interface|token|oracle|pair|pool|router|vault|verifier|bridge", t, re.I))


def _infer_role(name: str, type_name: str = "") -> tuple[str | None, float]:
    hay_name = name or ""
    hay_type = type_name or ""
    combined = f"{hay_name} {hay_type}"
    if re.search(r"ctoken|ictoken|vtoken|atoken|debttoken|c[A-Z][A-Za-z0-9_]*Token|v[A-Z][A-Za-z0-9_]*Token|a[A-Z][A-Za-z0-9_]*Token", combined):
        return "lending_market", 0.9
    best: tuple[str | None, float] = (None, 0.0)
    for role, pattern, _edges in _ROLE_RULES:
        score = 0.0
        if pattern.search(hay_name):
            score += 0.62
        if pattern.search(hay_type):
            score += 0.34
        if role == "asset" and hay_name.lower() in {"owner", "admin", "manager"}:
            score = 0.0
        if score > best[1]:
            best = (role, min(0.96, score))
    if best[1] < 0.34:
        return None, 0.0
    return best


def _edge_kind_for_role(role: str, default: str) -> str:
    for r, _pattern, edge_names in _ROLE_RULES:
        if r == role:
            return edge_names[0] if edge_names else default
    return default


def _edge_kind_for_method(method: str) -> str:
    low = method.lower()
    if any(k in low for k in ("price", "oracle", "quote", "latest", "converttoassets", "exchangerate", "twap")):
        return "reads_price_or_rate"
    if any(k in low for k in ("getaccountliquidity", "health", "shortfall", "collateral")):
        return "checks_liquidity"
    if any(k in low for k in ("borrow", "liquidat", "seize", "repay")):
        return "moves_debt"
    if any(k in low for k in ("transfer", "mint", "burn", "redeem", "withdraw", "deposit")):
        return "moves_asset"
    if any(k in low for k in ("sync", "skim", "getreserves", "slot0")):
        return "uses_amm_reserve"
    if any(k in low for k in ("verify", "proof")):
        return "verifies_proof"
    return "calls"


def _nodes_by_role(nodes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    roles: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in nodes:
        roles[str(node.get("role") or "unknown")].append(node)
    return roles


def _infer_surfaces(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], source_text: str) -> list[dict[str, Any]]:
    text = (source_text or "").lower()
    roles = _nodes_by_role(nodes)
    surfaces: list[dict[str, Any]] = []

    def node_ids(*role_names: str) -> list[str]:
        out: list[str] = []
        for role in role_names:
            out.extend(str(n.get("id")) for n in roles.get(role, []))
        return list(dict.fromkeys(out))[:12]

    has_lending = bool(roles.get("lending_controller") or roles.get("lending_market") or re.search(r"borrow|liquidat|getaccountliquidity|comptroller|ctoken", text))
    has_oracle = bool(roles.get("oracle") or re.search(r"getunderlyingprice|oracle|pricefeed|converttoassets|exchangerate", text))
    if has_lending and has_oracle:
        surfaces.append({
            "id": "oracle_lending",
            "title": "Oracle or exchange-rate component controls lending capacity",
            "severity": "high",
            "confidence": 0.75,
            "node_ids": node_ids("oracle", "lending_controller", "lending_market", "erc4626_vault", "asset"),
            "evidence": ["lending role and oracle/exchange-rate role both present"],
            "next": "Scan oracle, controller, cToken/market, wrapper/vault, and borrow asset together on a fork.",
        })

    if re.search(r"converttoassets|previewredeem|totalassets", text) and re.search(r"borrow|collateral|ltv|comptroller|liquidat", text):
        surfaces.append({
            "id": "erc4626_collateral_oracle",
            "title": "ERC-4626/share exchange rate appears in collateral or borrow context",
            "severity": "high",
            "confidence": 0.72,
            "node_ids": node_ids("erc4626_vault", "oracle", "lending_controller", "lending_market", "asset"),
            "evidence": ["ERC4626 rate terms co-occur with lending/collateral terms"],
            "next": "Fork: donate/loop the wrapper share rate, then borrow against the inflated collateral value.",
        })

    if roles.get("amm_pair") and re.search(r"\b(sync|skim|getreserves|slot0)\b", text):
        surfaces.append({
            "id": "amm_reserve_dependency",
            "title": "AMM pair/reserve component is part of accounting or pricing",
            "severity": "high" if re.search(r"_burn|burn|_update|accumulated|sync", text) else "medium",
            "confidence": 0.68,
            "node_ids": node_ids("amm_pair", "router", "asset"),
            "evidence": ["AMM pair role plus reserve/sync/spot-price terms"],
            "next": "Fork: skew reserves or trigger token-side pair balance mutation, then compare pool reserves and protocol accounting.",
        })

    if re.search(r"totalassets|convertoshares|converttoshares|deposit|redeem|withdraw", text) and re.search(r"share|supply|asset", text):
        surfaces.append({
            "id": "vault_share_accounting",
            "title": "Vault/share accounting boundary",
            "severity": "medium",
            "confidence": 0.62,
            "node_ids": node_ids("erc4626_vault", "asset", "strategy"),
            "evidence": ["vault/share accounting terms present"],
            "next": "Fuzz deposit, donation, withdrawal, redemption, and share/asset conservation invariants.",
        })

    if (roles.get("bridge_messenger") or roles.get("verifier")) and re.search(r"proof|root|message|nonce|verify|relay|process", text):
        surfaces.append({
            "id": "bridge_or_proof_domain",
            "title": "Bridge/proof/message domain boundary",
            "severity": "high",
            "confidence": 0.7,
            "node_ids": node_ids("bridge_messenger", "verifier", "asset"),
            "evidence": ["bridge/verifier roles co-occur with proof/root/message terms"],
            "next": "Check source/destination domain, nonce, root, verifier, receiver, asset, and replay marker binding.",
        })

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for surface in surfaces:
        if surface["id"] in seen:
            continue
        seen.add(surface["id"])
        unique.append(surface)
    return unique


def _companion_candidates(nodes: list[dict[str, Any]], target_address: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    target_low = (target_address or "").lower()
    seen: set[str] = set()
    for node in nodes:
        role = str(node.get("role") or "")
        if role not in _HIGH_VALUE_ROLES:
            continue
        address = node.get("address")
        if address and str(address).lower() == target_low:
            continue
        key = str(address or f"{role}:{node.get('label')}:{node.get('source')}").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "role": role,
            "label": node.get("label"),
            "address": address,
            "source": node.get("source"),
            "confidence": node.get("confidence"),
            "unresolved": not bool(address),
            "node_id": node.get("id"),
        })
    return out


def _build_groups(surfaces: list[dict[str, Any]], nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(n.get("id")): n for n in nodes}
    groups: list[dict[str, Any]] = []
    for surface in surfaces:
        members = [by_id[nid] for nid in surface.get("node_ids") or [] if nid in by_id]
        groups.append({
            "id": surface.get("id"),
            "title": surface.get("title"),
            "severity": surface.get("severity"),
            "members": [
                {
                    "label": m.get("label"),
                    "role": m.get("role"),
                    "address": m.get("address"),
                    "source": m.get("source"),
                }
                for m in members
            ],
        })
    return groups
