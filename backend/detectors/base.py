"""Detector framework: TargetContext, FindingCandidate, base Detector, and
lightweight (regex-based) Solidity helpers shared by detectors.

These helpers are intentionally heuristic — they surface *candidates*, never
confirmed bugs. Scoring + AI review downgrade/upgrade from here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cycles at runtime
    from ..core.onchain import OnchainClient
    from ..core.proxy_resolver import ProxyInfo
    from ..core.semantic_index import ContractFacts
    from ..core.taint import TaintReport


ULTRA_FAMILY_PROFILES = frozenset({"ultra-deep", "ultra-deep-v2"})


def is_ultra_profile(profile: str) -> bool:
    return profile in ULTRA_FAMILY_PROFILES


# --------------------------------------------------------------------------- #
@dataclass
class FindingCandidate:
    detector: str
    title: str
    description: str
    impact_score: float = 0.0  # 0-10
    confidence_score: float = 0.0  # 0-10 (pre-AI)
    severity_candidate: str = "info"  # critical/high/medium/low/info
    evidence: dict = field(default_factory=dict)
    next_tests: list[str] = field(default_factory=list)
    affected_functions: list[str] = field(default_factory=list)


@dataclass
class SolFunction:
    name: str
    params: str
    visibility: str  # public/external/internal/private/unknown
    modifiers: list[str]
    returns: str
    file: str
    line: int
    snippet: str
    has_access_control: bool


@dataclass
class TargetContext:
    address: str
    chain: str
    profile: str
    onchain: "OnchainClient"
    proxy_info: "ProxyInfo"
    workspace: Path
    contract_name: str = ""
    # Combined source: proxy + implementation files keyed by display path.
    source_files: dict[str, str] = field(default_factory=dict)
    abi: list | dict | None = None
    bytecode: str | None = None
    # Parsed tool summaries: {"slither": {...}, "mythril": {...}, ...}
    tool_outputs: dict = field(default_factory=dict)
    # Elite Phase 8: shared semantic/taint facts for detectors/reasoners.
    semantic: "ContractFacts | None" = None
    taint: "TaintReport | None" = None
    # Phase 12: per-target cross-contract role/surface graph.
    protocol_graph: dict | None = None
    # Phase 14: storage/proxy/module layout hints for validation and AI review.
    storage_layout: dict | None = None

    # ------------------------------------------------------------------ #
    def all_source_text(self) -> str:
        return "\n".join(self.source_files.values())

    def functions(self) -> list[SolFunction]:
        out: list[SolFunction] = []
        for path, text in self.source_files.items():
            out.extend(extract_functions(text, path))
        return out

    def abi_function_names(self) -> set[str]:
        names: set[str] = set()
        if isinstance(self.abi, list):
            for item in self.abi:
                if isinstance(item, dict) and item.get("type") == "function":
                    names.add(item.get("name", ""))
        return names


# --------------------------------------------------------------------------- #
# Solidity-lite parsing helpers
# --------------------------------------------------------------------------- #
ACCESS_CONTROL_MARKERS = (
    "onlyOwner",
    "onlyRole",
    "onlyAdmin",
    "onlyGovernance",
    "onlyGovernor",
    "onlyProxyAdmin",
    "proxyCallIfNotAdmin",
    "onlyUninitialized",
    "onlyTimelock",
    "onlySelf",
    "onlyManager",
    "onlyMinter",
    "requiresAuth",
    "authorized",
    "restricted",
    "onlyEntryPoint",
    "ifAdmin",
    "ifNotAdmin",
    "onlyProxy",
    "notDelegated",
)

_FUNC_RE = re.compile(
    r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^{};]*)",
    re.MULTILINE,
)
_VISIBILITY_RE = re.compile(r"\b(public|external|internal|private)\b")


def strip_comments(src: str) -> str:
    """Blank out // and /* */ comments while preserving length and newlines.

    Comments are replaced with spaces (newlines kept) so that character offsets
    and line numbers stay valid for snippet/line reporting, but commented-out
    code can never trigger a detector regex.
    """
    if not src:
        return src

    def _repl(m: re.Match) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in m.group(0))

    src = re.sub(r"/\*.*?\*/", _repl, src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", _repl, src)
    return src


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, pos: int, before: int = 1, after: int = 8) -> str:
    lines = text.splitlines()
    ln = _line_of(text, pos) - 1
    start = max(0, ln - before)
    end = min(len(lines), ln + after)
    return "\n".join(lines[start:end])


def extract_functions(source: str, file: str = "") -> list[SolFunction]:
    """Best-effort extraction of function declarations from Solidity source."""
    funcs: list[SolFunction] = []
    if not source:
        return funcs
    source = strip_comments(source)  # don't match commented-out declarations
    for m in _FUNC_RE.finditer(source):
        name = m.group(1)
        params = (m.group(2) or "").strip()
        tail = (m.group(3) or "").strip()
        vis_m = _VISIBILITY_RE.search(tail)
        visibility = vis_m.group(1) if vis_m else "unknown"
        # modifiers = identifiers in the tail that are not solidity keywords
        keywords = {
            "public",
            "external",
            "internal",
            "private",
            "view",
            "pure",
            "payable",
            "virtual",
            "override",
            "returns",
            "memory",
            "storage",
            "calldata",
        }
        modifiers = [
            tok
            for tok in re.findall(r"[A-Za-z_]\w*", tail)
            if tok not in keywords
        ]
        returns = ""
        rm = re.search(r"returns\s*\(([^)]*)\)", tail)
        if rm:
            returns = rm.group(1).strip()
        has_ac = any(mk.lower() in tail.lower() for mk in ACCESS_CONTROL_MARKERS) or any(
            mk.lower() in (mod.lower() for mod in modifiers) for mk in ACCESS_CONTROL_MARKERS
        )
        funcs.append(
            SolFunction(
                name=name,
                params=params,
                visibility=visibility,
                modifiers=modifiers,
                returns=returns,
                file=file,
                line=_line_of(source, m.start()),
                snippet=_snippet(source, m.start()),
                has_access_control=has_ac,
            )
        )
    return funcs


def is_externally_callable(fn: SolFunction) -> bool:
    return fn.visibility in ("public", "external", "unknown")


_FUNC_BODY_RE = re.compile(
    r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;]*)\{", re.MULTILINE
)


def iter_function_bodies(source: str):
    """Yield (name, params, header_tail, body) for each braced function.

    Shared by the v0.4 attack-class detectors so each one reasons over the WHOLE
    function body (and its modifiers via header_tail), not a truncated snippet.
    Comments are stripped first so commented-out code can never trigger a match.
    """
    if not source:
        return
    src = strip_comments(source)
    for m in _FUNC_BODY_RE.finditer(src):
        name = m.group(1)
        params = (m.group(2) or "").strip()
        tail = (m.group(3) or "").strip()
        start = m.end() - 1
        depth, i = 0, start
        n = len(src)
        while i < n:
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield name, params, tail, src[start : i + 1]


def header_has_access_control(header_tail: str) -> bool:
    t = (header_tail or "").lower()
    return any(mk.lower() in t for mk in ACCESS_CONTROL_MARKERS)


def role_hash(role_name: str) -> bytes:
    """keccak256 of a role name (OpenZeppelin AccessControl convention)."""
    from eth_utils import keccak

    if role_name == "DEFAULT_ADMIN_ROLE":
        return b"\x00" * 32
    return keccak(text=role_name)


# --------------------------------------------------------------------------- #
class Detector:
    """Base detector. Subclasses set ``name`` and implement ``run``."""

    name: str = "base"
    # Profiles this detector should run under (None => all profiles).
    profiles: tuple[str, ...] | None = None

    def applies(self, profile: str) -> bool:
        return self.profiles is None or profile in self.profiles

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:  # pragma: no cover
        raise NotImplementedError
