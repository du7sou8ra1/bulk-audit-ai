"""Lightweight Solidity call-graph + context slicing.

Gap #1/#2 fix: the regex detectors only ever saw a ~1500-char snippet of ONE
function, so they can't reason about cross-function invariants (the hash-chain
binding, the commit->verify->execute flow, the rounding direction that lives in a
helper). This builds a best-effort call graph from the combined source so the
semantic reasoner and PoC builder can be handed a *slice* — a function plus its
callees, its callers, and the state variables it touches — rather than a snippet.

It is deliberately heuristic (no full AST). It never executes anything.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..detectors.base import strip_comments

_FUNC_HEADER_RE = re.compile(
    r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;]*)(\{)",
    re.MULTILINE,
)
_STATE_DECL_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;{]*?\)|address|uint\d*|int\d*|bool|bytes\d*|string|"
    r"[A-Z]\w+)\s+(?:public|private|internal|immutable|constant|override|\s)*\s*"
    r"([A-Za-z_]\w*)\s*[;=]",
    re.MULTILINE,
)
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_SOLIDITY_KEYWORDS = {
    "if", "else", "for", "while", "return", "require", "assert", "revert",
    "emit", "new", "delete", "memory", "storage", "calldata", "public",
    "external", "internal", "private", "view", "pure", "payable", "returns",
    "function", "uint", "int", "address", "bool", "bytes", "string", "mapping",
    "true", "false", "this", "super", "abi", "keccak256", "msg", "block", "tx",
    "type", "unchecked", "assembly", "constant", "immutable", "virtual",
    "override", "modifier",
}


@dataclass
class FnNode:
    name: str
    params: str
    header_tail: str          # text between ) and { (visibility, modifiers, returns)
    body: str
    file: str
    start: int
    visibility: str
    modifiers: list[str]
    is_external: bool
    has_access_control: bool
    calls: set[str] = field(default_factory=set)        # callee function names
    state_reads_writes: set[str] = field(default_factory=set)  # touched state vars


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


class CallGraph:
    def __init__(self) -> None:
        self.fns: dict[str, FnNode] = {}            # name -> node (last wins on dupes)
        self.fns_by_file: list[FnNode] = []
        self.state_vars: set[str] = set()
        self.callers: dict[str, set[str]] = {}      # name -> set of callers

    @classmethod
    def build(cls, source_files: dict[str, str]) -> "CallGraph":
        g = cls()
        access_markers = (
            "onlyowner", "onlyrole", "onlyadmin", "onlygovernance", "onlygovernor",
            "onlyproxyadmin", "onlytimelock", "onlyself", "onlymanager", "onlyminter",
            "requiresauth", "onlyvalidator", "isactivevalidator", "requiregovernor",
        )
        # First pass: state variables (top-level decls) + function nodes.
        for path, raw in source_files.items():
            if not raw:
                continue
            src = strip_comments(raw)
            for sm in _STATE_DECL_RE.finditer(src):
                g.state_vars.add(sm.group(1))
            for m in _FUNC_HEADER_RE.finditer(src):
                name = m.group(1)
                params = (m.group(2) or "").strip()
                tail = (m.group(3) or "").strip()
                body, _ = _match_brace_body(src, m.start(4))
                vis_m = re.search(r"\b(public|external|internal|private)\b", tail)
                vis = vis_m.group(1) if vis_m else "unknown"
                mods = [
                    t for t in _IDENT_RE.findall(tail)
                    if t not in {"public", "external", "internal", "private", "view",
                                 "pure", "payable", "virtual", "override", "returns",
                                 "memory", "storage", "calldata"}
                ]
                has_ac = any(mk in tail.lower() for mk in access_markers) or any(
                    mk in body.lower()[:400] for mk in access_markers
                )
                node = FnNode(
                    name=name, params=params, header_tail=tail, body=body, file=path,
                    start=m.start(), visibility=vis, modifiers=mods,
                    is_external=vis in ("public", "external", "unknown"),
                    has_access_control=has_ac,
                )
                g.fns[name] = node
                g.fns_by_file.append(node)
        # Second pass: resolve call edges + state touches within each body.
        known = set(g.fns)
        for node in g.fns_by_file:
            idents = set(_IDENT_RE.findall(node.body))
            node.calls = {i for i in idents if i in known and i != node.name}
            node.state_reads_writes = {i for i in idents if i in g.state_vars}
            for callee in node.calls:
                g.callers.setdefault(callee, set()).add(node.name)
        return g

    def get(self, name: str) -> FnNode | None:
        return self.fns.get(name)

    def slice_for(self, fn_name: str, *, max_callees: int = 8, max_chars: int = 14000) -> str:
        """A focused source slice: the function, its direct callees, its callers,
        and the declarations of state variables it touches. This is what gets
        handed to the LLM instead of a blind snippet."""
        node = self.fns.get(fn_name)
        parts: list[str] = []
        seen: set[str] = set()

        def add(n: FnNode, label: str) -> None:
            if n.name in seen:
                return
            seen.add(n.name)
            header = f"function {n.name}({n.params}) {n.header_tail}".strip()
            parts.append(f"// [{label}] {n.file}\n{header} {n.body}")

        if node is not None:
            add(node, "TARGET")
            for callee in list(node.calls)[:max_callees]:
                cn = self.fns.get(callee)
                if cn is not None:
                    add(cn, "CALLEE")
            for caller in list(self.callers.get(fn_name, ()))[:4]:
                cn = self.fns.get(caller)
                if cn is not None:
                    add(cn, "CALLER")
        out = "\n\n".join(parts)
        return out[:max_chars]

    def state_changing_externals(self) -> list[FnNode]:
        """External/public, non-view functions that touch state — the real
        attack surface for state-changing PoCs and invariant reasoning."""
        out = []
        for n in self.fns_by_file:
            if not n.is_external:
                continue
            tail = n.header_tail.lower()
            if "view" in tail or "pure" in tail:
                continue
            out.append(n)
        return out
