"""Detectors: upgradeable-implementation safety (proxy-backed logic contracts).

Two classes the existing access-control / reinit detectors miss (verified via the
gap-hunt probe against the live engine):

1. UninitializedImplementation — an Initializable/UUPS implementation that HAS an
   `initializer`-guarded `initialize()` but whose constructor never calls
   `_disableInitializers()`. The impl itself can be initialized by anyone, who then
   becomes owner and (for UUPS) can `upgradeToAndCall` a selfdestruct/delegatecall.
   Wormhole ($320M near-miss) / OZ security advisory class.

2. ConstructorStateInProxyImpl — an upgradeable impl that declares `immutable`
   (non-constant) state. Immutables live in the impl's own code/constructor, so
   behind a proxy the value is whatever the IMPL was deployed with (often the impl's
   own deployer / address(0)), diverging from proxy storage — broken/bypassable auth.

Both are marker-gated on (upgradeable + initialize) so they never touch ordinary
non-proxy contracts.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies

_UPGRADEABLE_RE = re.compile(
    r"\bInitializable\b|\bUUPSUpgradeable\b|[A-Za-z]\w*Upgradeable\b|"
    r"_authorizeUpgrade\s*\(|__\w+_init\s*\(|ERC1967",
)
_INIT_MODIFIER_RE = re.compile(r"\binitializer\b|\breinitializer\s*\(")
_DISABLE_RE = re.compile(r"_disableInitializers\s*\(")
_INITIALIZE_FN_RE = re.compile(r"^(initialize|__\w+_init|reinitialize)\w*$", re.I)
# a declared immutable that is NOT a compile-time constant
_IMMUTABLE_DECL_RE = re.compile(r"\bimmutable\b")
_IS_ABSTRACT_RE = re.compile(r"\babstract\s+contract\b")
_UPGRADEABLE_BASE_RE = re.compile(r"\bInitializable\b|[A-Za-z]\w*Upgradeable\b")
_GAP_RE = re.compile(r"__gap\b|_gap\b")
# A state variable carries a visibility keyword (locals do not) and is not const/immutable.
_STATE_VAR_RE = re.compile(
    r"^\s*(?:uint\d*|int\d*|address|bool|bytes\d*|mapping\s*\(|string)\b[^;{}]*\b(?:public|private|internal)\b[^;{}]*;",
    re.MULTILINE,
)


def _looks_upgradeable(text: str) -> bool:
    return bool(_UPGRADEABLE_RE.search(text) and _INIT_MODIFIER_RE.search(text))


def _initialize_fn_name(text: str) -> str:
    for fname, _p, tail, _b in iter_function_bodies(text):
        if _INIT_MODIFIER_RE.search(tail) or _INITIALIZE_FN_RE.match(fname):
            return fname
    return ""


class UninitializedImplementationDetector(Detector):
    name = "uninitialized_implementation"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _looks_upgradeable(source):
                continue
            # OZ's own Initializable.sol defines _disableInitializers -> token present -> safe.
            if _DISABLE_RE.search(source):
                continue
            # Skip pure abstract bases with no initialize() of their own.
            init_fn = _initialize_fn_name(source)
            if not init_fn:
                continue
            out.append(FindingCandidate(
                detector="uninitialized_implementation",
                title=f"Upgradeable implementation never calls _disableInitializers(): {init_fn}",
                description=(
                    f"This Initializable/UUPS implementation exposes `{init_fn}()` guarded by the "
                    "`initializer` modifier but its constructor never calls `_disableInitializers()`. "
                    "The implementation contract itself is left uninitialized, so anyone can call "
                    f"`{init_fn}` directly on the impl address, become owner, and (for UUPS) "
                    "`upgradeToAndCall` to a selfdestruct/delegatecall. Add a "
                    "`constructor() { _disableInitializers(); }` (Wormhole / OZ advisory class)."
                ),
                impact_score=9.0,
                confidence_score=6.0,  # -> LIKELY_CRITICAL_NEEDS_POC
                severity_candidate="critical",
                evidence={
                    "function": init_fn, "file": path, "bug_class": "uninitialized_implementation",
                    "unprivileged": True, "needs_poc": True,
                },
                next_tests=[
                    "Call initialize() directly on the implementation address on a fork; expect success",
                    "Confirm no _disableInitializers() runs in the impl constructor",
                ],
                affected_functions=[init_fn],
            ))
        return out


class ConstructorStateInProxyImplDetector(Detector):
    name = "constructor_state_in_proxy_impl"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _looks_upgradeable(source):
                continue
            init_fn = _initialize_fn_name(source)
            if not init_fn:
                continue
            # immutable (non-constant) state in an upgradeable impl is the bug.
            # Exclude lines where 'immutable' co-occurs with 'constant' (rare) by
            # scanning declaration lines individually.
            bad = [
                ln.strip() for ln in source.splitlines()
                if _IMMUTABLE_DECL_RE.search(ln) and "constant" not in ln and "(" not in ln.split("immutable")[0][-40:]
            ]
            if not bad:
                continue
            out.append(FindingCandidate(
                detector="constructor_state_in_proxy_impl",
                title="Upgradeable implementation declares immutable/constructor state (proxy divergence)",
                description=(
                    "This upgradeable (Initializable/UUPS) implementation declares `immutable` state. "
                    "Immutables are baked into the implementation's own bytecode, not proxy storage, so "
                    "behind a proxy the value is whatever the impl was deployed with (often the impl "
                    "deployer or address(0)) rather than the initialized value — leading to broken or "
                    "bypassable auth/config. Move these into `initialize()` as regular storage."
                ),
                impact_score=7.0,
                confidence_score=5.0,  # -> NEEDS_MORE_INVESTIGATION (lead)
                severity_candidate="high",
                evidence={
                    "file": path, "bug_class": "constructor_state_in_proxy_impl",
                    "immutable_decls": bad[:5], "needs_poc": True,
                },
                next_tests=[
                    "Read the immutable-backed getter via the PROXY address; confirm it differs from the initialized value",
                    "Confirm the value is not re-set in initialize()",
                ],
                affected_functions=[init_fn],
            ))
        return out


class MissingStorageGapDetector(Detector):
    """An inheritable upgradeable base with mutable state but no trailing __gap array —
    future storage additions collide with child storage on upgrade. Gated on `abstract`
    + upgradeable base + a visibility-carrying state var, to stay off leaf/non-proxy code."""
    name = "missing_storage_gap"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or not _IS_ABSTRACT_RE.search(source):
                continue
            if not _UPGRADEABLE_BASE_RE.search(source):
                continue
            if _GAP_RE.search(source):
                continue
            if not _STATE_VAR_RE.search(source):
                continue
            out.append(FindingCandidate(
                detector="missing_storage_gap",
                title="Upgradeable base declares state but reserves no __gap",
                description=(
                    "This inheritable upgradeable base (abstract + Initializable/*Upgradeable) declares mutable "
                    "state but has no trailing `uint256[N] private __gap;`. When the base later adds a storage "
                    "variable, it collides with the child contract's storage across an upgrade, corrupting it. "
                    "Reserve a `__gap` array sized so the base's storage footprint stays fixed."
                ),
                impact_score=6.0,
                confidence_score=4.0,  # LOW_OR_INFO / lead
                severity_candidate="medium",
                evidence={"file": path, "bug_class": "missing_storage_gap", "needs_poc": True},
                next_tests=[
                    "Add a state var to the base and diff the storage layout of a child before/after; expect a collision",
                    "Confirm the base is inherited by an upgradeable child",
                ],
                affected_functions=[],
            ))
        return out
