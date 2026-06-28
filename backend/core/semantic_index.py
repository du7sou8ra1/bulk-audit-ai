"""Best-effort Solidity semantic index.

This module is deliberately heuristic: it does not try to be a full Solidity AST.
It gives detectors a richer, shared view of the target than raw regex snippets:
function params, modifiers, guards, state reads/writes, internal calls, external
calls, value sinks, decoded calldata fields, and entrypoint reachability.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..detectors.base import strip_comments

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_FUNC_HEADER_RE = re.compile(
    r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{};]*)(\{)",
    re.MULTILINE,
)
_VISIBILITY_RE = re.compile(r"\b(public|external|internal|private)\b")
_MUTABILITY_RE = re.compile(r"\b(view|pure|payable)\b")
_REQUIRE_RE = re.compile(r"\b(require|assert)\s*\((.*?)\)\s*;", re.DOTALL)
_REVERT_RE = re.compile(r"\brevert\s+([^;]+);", re.DOTALL)
_EMIT_RE = re.compile(r"\bemit\s+([A-Za-z_]\w*)\s*\(")
_ABI_DECODE_RE = re.compile(r"(?:\((?P<tuple>[^)]*)\)|(?P<single>[A-Za-z_]\w*))\s*=\s*abi\.decode\s*\(", re.DOTALL)

_SOLIDITY_TAIL_KEYWORDS = {
    "public", "external", "internal", "private", "view", "pure", "payable",
    "virtual", "override", "returns", "memory", "storage", "calldata",
}
_PARAM_NOISE = {"memory", "storage", "calldata", "payable"}
_ACCESS_HINT_RE = re.compile(
    r"^(only[A-Z_]|.*Only$|.*Guard$|restricted$|requiresAuth$|auth$|isAuthorized$)",
    re.I,
)
_SOURCE_NAME_RE = re.compile(
    r"proof|proofData|payload|message|data|pubdata|signature|sig|recipient|receiver|to|amount|token|asset|root|nonce|src|source|chain",
    re.I,
)

_VALUE_METHODS = {
    "transfer", "send", "safeTransfer", "safeTransferFrom", "transferFrom",
    "call", "_mint", "mint", "_burn", "burn",
}
_LOW_LEVEL_METHODS = {"call", "delegatecall", "staticcall"}
_EXTERNAL_CALL_RE = re.compile(
    r"(?P<target>[A-Za-z_]\w*(?:\s*\[[^\]]+\]|(?:\.[A-Za-z_]\w*)|(?:\([^;{}]*\)))*)"
    r"\s*\.\s*(?P<kind>call|delegatecall|staticcall|transfer|send|safeTransfer|safeTransferFrom|transferFrom)"
    r"\s*(?:\{(?P<options>[^}]*)\})?\s*\((?P<args>[^;{}]*)\)",
    re.DOTALL,
)
_MINT_BURN_RE = re.compile(r"\b(?P<kind>_?mint|_?burn)\s*\((?P<args>[^;{}]*)\)", re.DOTALL)

_MAPPING_RE = re.compile(
    r"mapping\s*\((?P<key>[^=;{}]+)=>\s*(?P<value>[^)]+)\)\s*"
    r"(?P<attrs>(?:public|private|internal|constant|immutable|override|\s)*)"
    r"(?P<name>[A-Za-z_]\w*)\s*[;=]",
    re.MULTILINE,
)
_STATE_RE = re.compile(
    r"^\s*(?P<type>[A-Za-z_]\w*(?:\s+payable)?(?:\[\])?|address\s+payable|uint\d*|int\d*|bytes\d*|bytes|string|bool)\s+"
    r"(?P<attrs>(?:(?:public|private|internal|constant|immutable|override)\s+)*)"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=|;)",
    re.MULTILINE,
)


@dataclass
class FunctionFacts:
    name: str
    file: str
    line: int
    params: list[dict[str, str]]
    tail: str
    body: str
    visibility: str
    mutability: str
    modifiers: list[str]
    guards: list[str] = field(default_factory=list)
    reads: set[str] = field(default_factory=set)
    writes: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)
    external_calls: list[dict[str, Any]] = field(default_factory=list)
    value_sinks: list[dict[str, Any]] = field(default_factory=list)
    taint_sources: set[str] = field(default_factory=set)
    decoded_fields: set[str] = field(default_factory=set)
    events: set[str] = field(default_factory=set)

    @property
    def is_entrypoint(self) -> bool:
        return self.visibility in {"public", "external", "unknown"}


@dataclass
class ContractFacts:
    state_vars: dict[str, dict[str, Any]] = field(default_factory=dict)
    mappings: dict[str, dict[str, Any]] = field(default_factory=dict)
    functions: dict[str, FunctionFacts] = field(default_factory=dict)
    functions_by_key: dict[str, FunctionFacts] = field(default_factory=dict)
    call_edges: dict[str, set[str]] = field(default_factory=dict)
    callers: dict[str, set[str]] = field(default_factory=dict)
    entrypoints: set[str] = field(default_factory=set)
    abi_functions: set[str] = field(default_factory=set)

    def get_function(self, name: str) -> FunctionFacts | None:
        return self.functions.get(name) or self.functions_by_key.get(name)

    def external_entrypoints_reaching(self, function_name: str) -> set[str]:
        out: set[str] = set()
        for entry in self.entrypoints:
            if function_name in reachable_functions(self, entry):
                out.add(entry)
        return out


def build_semantic_index(source_files: dict[str, str], abi: list | dict | None = None) -> ContractFacts:
    facts = ContractFacts(abi_functions=_abi_function_names(abi))
    if not source_files:
        return facts

    for path, raw in source_files.items():
        if not raw:
            continue
        src = strip_comments(raw)
        contract_level = _contract_level_source(src)
        _collect_state_vars(facts, contract_level, path)
        _collect_functions(facts, src, path)

    known = set(facts.functions)
    for fn in facts.functions_by_key.values():
        idents = set(_IDENT_RE.findall(fn.body))
        fn.calls = {name for name in known if name != fn.name and re.search(rf"\b{re.escape(name)}\s*\(", fn.body)}
        fn.reads = {name for name in idents if name in facts.state_vars or name in facts.mappings}
        fn.writes = _state_writes(fn.body, set(facts.state_vars) | set(facts.mappings))
        _mark_write_order(fn)
        facts.call_edges.setdefault(fn.name, set()).update(fn.calls)
        for callee in fn.calls:
            facts.callers.setdefault(callee, set()).add(fn.name)
        if fn.is_entrypoint or fn.name in facts.abi_functions:
            facts.entrypoints.add(fn.name)
    return facts


def reachable_functions(facts: ContractFacts, entrypoint: str, *, max_depth: int = 8) -> set[str]:
    seen: set[str] = set()
    stack: list[tuple[str, int]] = [(entrypoint, 0)]
    while stack:
        name, depth = stack.pop()
        if name in seen or depth > max_depth:
            continue
        seen.add(name)
        for callee in facts.call_edges.get(name, set()):
            stack.append((callee, depth + 1))
    return seen


def _abi_function_names(abi: list | dict | None) -> set[str]:
    items = abi.get("abi") if isinstance(abi, dict) else abi
    names: set[str] = set()
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("type") == "function" and item.get("name"):
                names.add(str(item["name"]))
    return names


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _match_brace_body(text: str, open_idx: int) -> tuple[str, int]:
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx : i + 1], i + 1
        i += 1
    return text[open_idx:], n


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


def _collect_state_vars(facts: ContractFacts, src: str, path: str) -> None:
    for m in _MAPPING_RE.finditer(src):
        name = m.group("name")
        facts.mappings[name] = {
            "name": name,
            "type": "mapping",
            "key_type": m.group("key").strip(),
            "value_type": m.group("value").strip(),
            "attrs": m.group("attrs").split(),
            "file": path,
            "line": _line_of(src, m.start()),
        }
        facts.state_vars.setdefault(name, facts.mappings[name])

    for m in _STATE_RE.finditer(src):
        line = src[m.start() : src.find("\n", m.start()) if src.find("\n", m.start()) != -1 else len(src)]
        if re.search(r"\b(function|modifier|event|error|struct|enum|contract|interface|library)\b", line):
            continue
        name = m.group("name")
        if name in facts.state_vars:
            continue
        facts.state_vars[name] = {
            "name": name,
            "type": re.sub(r"\s+", " ", m.group("type").strip()),
            "attrs": (m.group("attrs") or "").split(),
            "file": path,
            "line": _line_of(src, m.start()),
        }


def _collect_functions(facts: ContractFacts, src: str, path: str) -> None:
    for m in _FUNC_HEADER_RE.finditer(src):
        name = m.group(1)
        params = _parse_params(m.group(2) or "")
        tail = (m.group(3) or "").strip()
        body, _ = _match_brace_body(src, m.start(4))
        vis_m = _VISIBILITY_RE.search(tail)
        mut_m = _MUTABILITY_RE.search(tail)
        modifiers = _parse_modifiers(tail)
        fn = FunctionFacts(
            name=name,
            file=path,
            line=_line_of(src, m.start()),
            params=params,
            tail=tail,
            body=body,
            visibility=vis_m.group(1) if vis_m else "unknown",
            mutability=mut_m.group(1) if mut_m else "nonpayable",
            modifiers=modifiers,
            guards=_guards(tail, body, modifiers),
            external_calls=_external_calls(body),
            value_sinks=_value_sinks(body),
            taint_sources=_taint_sources(params, body),
            decoded_fields=_decoded_fields(body),
            events=set(_EMIT_RE.findall(body)),
        )
        key = f"{path}:{name}:{fn.line}"
        facts.functions_by_key[key] = fn
        facts.functions[name] = fn


def _split_top_level(value: str, sep: str = ",") -> list[str]:
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(value):
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            out.append(value[start:i].strip())
            start = i + 1
    tail = value[start:].strip()
    if tail:
        out.append(tail)
    return out


def _parse_params(params: str) -> list[dict[str, str]]:
    parsed: list[dict[str, str]] = []
    for idx, part in enumerate(_split_top_level(params)):
        if not part:
            continue
        toks = _IDENT_RE.findall(part)
        name = ""
        if toks:
            last = toks[-1]
            if last not in _PARAM_NOISE and last not in {"uint", "int", "address", "bool", "string", "bytes"}:
                name = last
        if not name:
            name = f"arg{idx}"
        ptype = part.rsplit(name, 1)[0].strip() if name in part else part.strip()
        parsed.append({"name": name, "type": re.sub(r"\s+", " ", ptype).strip(), "raw": part})
    return parsed


def _parse_modifiers(tail: str) -> list[str]:
    clean = re.sub(r"returns\s*\([^)]*\)", " ", tail)
    mods: list[str] = []
    for tok in _IDENT_RE.findall(clean):
        if tok in _SOLIDITY_TAIL_KEYWORDS:
            continue
        mods.append(tok)
    return mods


def _guards(tail: str, body: str, modifiers: list[str]) -> list[str]:
    guards: list[str] = []
    for mod in modifiers:
        if _ACCESS_HINT_RE.search(mod):
            guards.append(mod)
    for m in _REQUIRE_RE.finditer(body):
        guards.append(re.sub(r"\s+", " ", f"{m.group(1)}({m.group(2)})").strip()[:300])
    for m in _REVERT_RE.finditer(body):
        guards.append(re.sub(r"\s+", " ", f"revert {m.group(1)}").strip()[:300])
    if re.search(r"hasRole\s*\(|msg\.sender\s*==|_msgSender\s*\(\s*\)\s*==", body):
        guards.append("inline_sender_or_role_check")
    return guards


def _external_calls(body: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for m in _EXTERNAL_CALL_RE.finditer(body):
        calls.append(
            {
                "target": re.sub(r"\s+", " ", m.group("target")).strip(),
                "kind": m.group("kind"),
                "args": re.sub(r"\s+", " ", (m.group("args") or "")).strip(),
                "value": _extract_value_option(m.group("options") or ""),
                "data": re.sub(r"\s+", " ", (m.group("args") or "")).strip(),
                "position": m.start(),
                "before_state_update": False,
            }
        )
    return calls


def _value_sinks(body: str) -> list[dict[str, Any]]:
    sinks: list[dict[str, Any]] = []
    for call in _external_calls(body):
        if call["kind"] in _VALUE_METHODS:
            sinks.append({**call, "sink": call["kind"]})
    for m in _MINT_BURN_RE.finditer(body):
        kind = m.group("kind")
        sinks.append(
            {
                "target": "self",
                "kind": kind,
                "sink": kind,
                "args": re.sub(r"\s+", " ", m.group("args") or "").strip(),
                "value": "",
                "data": "",
                "position": m.start(),
                "before_state_update": False,
            }
        )
    return sinks


def _extract_value_option(options: str) -> str:
    m = re.search(r"\bvalue\s*:\s*([^,}]+)", options)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _state_writes(body: str, names: set[str]) -> set[str]:
    writes: set[str] = set()
    for name in names:
        n = re.escape(name)
        if re.search(rf"\bdelete\s+{n}\b", body):
            writes.add(name)
        if re.search(rf"\b{n}\s*(?:\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|%=|\+\+|--)", body):
            writes.add(name)
        if re.search(rf"\b{n}\s*\.\s*(?:push|pop)\s*\(", body):
            writes.add(name)
    return writes


def _mark_write_order(fn: FunctionFacts) -> None:
    if not fn.writes:
        return
    positions: list[int] = []
    for name in fn.writes:
        positions.extend(_state_write_positions(fn.body, name))
    if not positions:
        return
    for row in fn.external_calls:
        row["before_state_update"] = any(pos > int(row.get("position", 0)) for pos in positions)
    for row in fn.value_sinks:
        row["before_state_update"] = any(pos > int(row.get("position", 0)) for pos in positions)


def _state_write_positions(body: str, name: str) -> list[int]:
    n = re.escape(name)
    patterns = (
        rf"\bdelete\s+{n}\b",
        rf"\b{n}\s*(?:\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|%=|\+\+|--)",
        rf"\b{n}\s*\.\s*(?:push|pop)\s*\(",
    )
    out: list[int] = []
    for pat in patterns:
        out.extend(m.start() for m in re.finditer(pat, body))
    return out


def _taint_sources(params: list[dict[str, str]], body: str) -> set[str]:
    out = {p["name"] for p in params if p.get("name")}
    if "msg.sender" in body:
        out.add("msg.sender")
    if "_msgSender" in body:
        out.add("_msgSender()")
    if "msg.value" in body:
        out.add("msg.value")
    if "tx.origin" in body:
        out.add("tx.origin")
    if "abi.decode" in body:
        out.add("abi.decode")
    for p in params:
        if _SOURCE_NAME_RE.search(p.get("name", "")) or _SOURCE_NAME_RE.search(p.get("type", "")):
            out.add(p["name"])
    out.update(_decoded_fields(body))
    return {x for x in out if x}


def _decoded_fields(body: str) -> set[str]:
    out: set[str] = set()
    for m in _ABI_DECODE_RE.finditer(body):
        raw = m.group("tuple") or m.group("single") or ""
        for part in _split_top_level(raw):
            toks = _IDENT_RE.findall(part)
            if toks:
                out.add(toks[-1])
    return out
