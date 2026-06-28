"""Small taint/dataflow helpers over the semantic index.

The goal is not formal verification. It is a shared, conservative signal for
rare-bug detectors: caller/proof/calldata-controlled values reaching value
transfers, delegatecalls, upgrade sinks, replay markers, and accounting writes,
including simple external -> internal helper paths.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .semantic_index import ContractFacts, FunctionFacts, reachable_functions

_SUSPICIOUS_VALUE_NAMES = re.compile(
    r"recipient|receiver|to|dst|amount|value|token|asset|share|shares|root|proof|proofData|payload|message|nonce|index|fee|relayer",
    re.I,
)
_REPLAY_WRITE_RE = re.compile(r"processed|consumed|spent|nullifier|claimed|used", re.I)
_ACCOUNTING_WRITE_RE = re.compile(r"debt|collateral|reward|share|shares|balance|balances|supply|reserve|checkpoint|index|acc", re.I)
_UPGRADE_RE = re.compile(r"upgradeTo|upgradeToAndCall|setImplementation|setBeacon|diamondCut|setFacet|implementation", re.I)
_ORACLE_SOURCE_RE = re.compile(r"latestRoundData\s*\(|getReserves\s*\(|slot0\s*\(|balanceOf\s*\(\s*address\s*\(\s*this\s*\)", re.I)


@dataclass
class TaintFlow:
    entrypoint: str
    function: str
    source: str
    source_kind: str
    sink: str
    sink_kind: str
    path: list[str]
    variable: str = ""
    confidence: float = 0.0
    cross_function: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintReport:
    flows: list[TaintFlow] = field(default_factory=list)

    def by_sink(self, sink_kind: str) -> list[TaintFlow]:
        return [f for f in self.flows if f.sink_kind == sink_kind]

    def by_source(self, source_kind: str) -> list[TaintFlow]:
        return [f for f in self.flows if f.source_kind == source_kind]


def analyze_taint(facts: ContractFacts) -> TaintReport:
    report = TaintReport()
    for entry in sorted(facts.entrypoints):
        entry_fn = facts.get_function(entry)
        if entry_fn is None:
            continue
        sources = _sources_for(entry_fn)
        for fn_name in sorted(reachable_functions(facts, entry)):
            fn = facts.get_function(fn_name)
            if fn is None:
                continue
            path = _path_between(facts, entry, fn_name)
            for sink in _sinks_for(fn):
                matches = _matching_sources(facts, entry_fn, fn, sink, sources)
                for source_kind, source_name, confidence, reason in matches:
                    report.flows.append(
                        TaintFlow(
                            entrypoint=entry,
                            function=fn.name,
                            source=source_name,
                            source_kind=source_kind,
                            sink=sink["label"],
                            sink_kind=sink["kind"],
                            path=path,
                            variable=sink.get("variable", ""),
                            confidence=confidence,
                            cross_function=entry != fn.name,
                            evidence={
                                "reason": reason,
                                "sink_text": sink.get("text", ""),
                                "file": fn.file,
                                "line": fn.line,
                            },
                        )
                    )
    return report


def flows_to_sink(
    facts: ContractFacts,
    *,
    source: str = "calldata",
    sink: str = "value_transfer",
    min_confidence: float = 0.4,
) -> list[TaintFlow]:
    return [
        flow for flow in analyze_taint(facts).flows
        if flow.source_kind == source and flow.sink_kind == sink and flow.confidence >= min_confidence
    ]


def external_entrypoints_reaching(facts: ContractFacts, function_name: str) -> set[str]:
    return facts.external_entrypoints_reaching(function_name)


def _sources_for(fn: FunctionFacts) -> dict[str, set[str]]:
    sources: dict[str, set[str]] = {
        "calldata": set(),
        "msg_sender": set(),
        "msg_value": set(),
        "proof_data": set(),
        "oracle": set(),
    }
    if fn.is_entrypoint:
        sources["calldata"].update(p["name"] for p in fn.params if p.get("name"))
    for item in fn.taint_sources | fn.decoded_fields:
        if item in {"msg.sender", "_msgSender()"}:
            sources["msg_sender"].add(item)
        elif item == "msg.value":
            sources["msg_value"].add(item)
        elif item == "tx.origin":
            sources["msg_sender"].add(item)
        elif item == "abi.decode":
            sources["calldata"].add(item)
        else:
            sources["calldata"].add(item)
            if _is_proof_like(item):
                sources["proof_data"].add(item)
    if _ORACLE_SOURCE_RE.search(fn.body):
        sources["oracle"].add("oracle_read")
    return {k: {v for v in vals if v} for k, vals in sources.items()}


def _is_proof_like(name: str) -> bool:
    return bool(re.search(r"proof|payload|message|data|pubdata|root|nonce|signature|sig", name, re.I))


def _sinks_for(fn: FunctionFacts) -> list[dict[str, str]]:
    sinks: list[dict[str, str]] = []
    for row in fn.value_sinks:
        text = " ".join(str(row.get(k, "")) for k in ("target", "kind", "args", "value", "data"))
        sinks.append({"kind": "value_transfer", "label": str(row.get("sink") or row.get("kind")), "text": text})
    for row in fn.external_calls:
        kind = str(row.get("kind", ""))
        text = " ".join(str(row.get(k, "")) for k in ("target", "kind", "args", "value", "data"))
        if kind == "delegatecall":
            sinks.append({"kind": "delegatecall", "label": "delegatecall", "text": text})
        elif kind == "call":
            sinks.append({"kind": "low_level_call", "label": "call", "text": text})
    for call in fn.calls:
        if _UPGRADE_RE.search(call):
            sinks.append({"kind": "upgrade", "label": call, "text": call})
    for var in fn.writes:
        write_text = _write_text(fn.body, var) or var
        if _REPLAY_WRITE_RE.search(var):
            sinks.append({"kind": "replay_marker", "label": f"write:{var}", "text": write_text, "variable": var})
        if _ACCOUNTING_WRITE_RE.search(var):
            sinks.append({"kind": "accounting_write", "label": f"write:{var}", "text": write_text, "variable": var})
    return sinks


def _write_text(body: str, var: str) -> str:
    pat = re.compile(rf"[^;{{}}]*\b{re.escape(var)}\b(?:\s*\[[^\]]+\])?[^;{{}}]*(?:=|\+=|-=|\+\+|--)[^;{{}}]*", re.DOTALL)
    m = pat.search(body)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(0)).strip()[:500]


def _matching_sources(
    facts: ContractFacts,
    entry_fn: FunctionFacts,
    sink_fn: FunctionFacts,
    sink: dict[str, str],
    sources: dict[str, set[str]],
) -> list[tuple[str, str, float, str]]:
    out: list[tuple[str, str, float, str]] = []
    sink_text = sink.get("text", "") or ""
    sink_kind = sink.get("kind", "")

    for kind, names in sources.items():
        for name in names:
            if _name_in_text(name, sink_text):
                out.append((kind, name, 0.9, "source appears directly in sink expression"))
                continue
            if entry_fn.name != sink_fn.name and _source_passed_to_helper(entry_fn, sink_fn, name, sink_text):
                out.append((kind, name, 0.75, "entrypoint source is passed to internal helper sink"))

    if sink_kind in {"value_transfer", "accounting_write", "replay_marker"}:
        for decoded in sink_fn.decoded_fields:
            if _name_in_text(decoded, sink_text) or _SUSPICIOUS_VALUE_NAMES.search(decoded):
                out.append(("calldata", decoded, 0.8, "abi.decode field reaches sink"))
        if entry_fn.name != sink_fn.name and _SUSPICIOUS_VALUE_NAMES.search(sink_text):
            out.append(("calldata", "cross_function_args", 0.45, "reachable helper sink uses value-like arguments"))

    if sink_kind in {"delegatecall", "low_level_call", "upgrade"}:
        for name in sources.get("calldata", set()):
            if _name_in_text(name, sink_text) or _SUSPICIOUS_VALUE_NAMES.search(sink_text):
                out.append(("calldata", name, 0.8, "caller-controlled call target/data may reach call sink"))

    if sink_kind in {"value_transfer", "accounting_write"} and sources.get("oracle"):
        out.append(("oracle", "oracle_read", 0.55, "oracle/reserve/balance read influences value/accounting function"))

    return _dedup_matches(out)


def _name_in_text(name: str, text: str) -> bool:
    if not name or name in {"abi.decode", "oracle_read"}:
        return False
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return name in text
    return bool(re.search(rf"\b{re.escape(name)}\b", text))


def _source_passed_to_helper(entry_fn: FunctionFacts, sink_fn: FunctionFacts, source_name: str, sink_text: str) -> bool:
    calls = _call_args(entry_fn.body, sink_fn.name)
    if not calls:
        return False
    helper_params = [p["name"] for p in sink_fn.params if p.get("name")]
    for args in calls:
        for idx, arg in enumerate(_split_args(args)):
            if not _name_in_text(source_name, arg):
                continue
            if idx < len(helper_params) and _name_in_text(helper_params[idx], sink_text):
                return True
            if _SUSPICIOUS_VALUE_NAMES.search(sink_text):
                return True
    return False


def _call_args(body: str, callee: str) -> list[str]:
    out: list[str] = []
    pattern = re.compile(rf"\b{re.escape(callee)}\s*\(", re.MULTILINE)
    for m in pattern.finditer(body):
        start = m.end()
        depth = 1
        i = start
        while i < len(body):
            ch = body[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    out.append(body[start:i])
                    break
            i += 1
    return out


def _split_args(args: str) -> list[str]:
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(args):
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            out.append(args[start:i].strip())
            start = i + 1
    tail = args[start:].strip()
    if tail:
        out.append(tail)
    return out


def _path_between(facts: ContractFacts, start: str, goal: str) -> list[str]:
    if start == goal:
        return [start]
    queue: list[list[str]] = [[start]]
    seen = {start}
    while queue:
        path = queue.pop(0)
        for nxt in sorted(facts.call_edges.get(path[-1], set())):
            if nxt in seen:
                continue
            npath = path + [nxt]
            if nxt == goal:
                return npath
            seen.add(nxt)
            queue.append(npath)
    return [start, goal]


def _dedup_matches(rows: list[tuple[str, str, float, str]]) -> list[tuple[str, str, float, str]]:
    best: dict[tuple[str, str], tuple[str, str, float, str]] = {}
    for row in rows:
        key = (row[0], row[1])
        if key not in best or row[2] > best[key][2]:
            best[key] = row
    return list(best.values())
