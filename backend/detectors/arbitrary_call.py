"""Detector: arbitrary external call / delegatecall with user-controlled target.

Flags externally-callable functions that perform ``.call`` / ``.delegatecall``
where the target or calldata appears to come from function parameters and no
access control is present. delegatecall is treated as higher impact (it can
overwrite the calling contract's storage / hijack the proxy).
"""
from __future__ import annotations

import re

from .base import (
    Detector,
    FindingCandidate,
    TargetContext,
    extract_functions,
    strip_comments,
)

# Body-level patterns indicating a low-level call.
_CALL_RE = re.compile(r"\.\s*(delegatecall|call)\s*[({]")


def _function_bodies(source: str):
    """Yield (header_match, body_text) for each function with a brace body."""
    for m in re.finditer(r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)[^{;]*\{", source):
        start = m.end() - 1  # position of opening brace
        depth = 0
        i = start
        while i < len(source):
            c = source[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = source[start : i + 1]
        yield m, body


class ArbitraryCallDetector(Detector):
    name = "arbitrary_call"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        for path, source in ctx.source_files.items():
            if not source:
                continue
            source = strip_comments(source)  # commented-out calls must not match
            # Map function name -> SolFunction for access-control lookup.
            fn_index = {f.name: f for f in extract_functions(source, path)}

            for m, body in _function_bodies(source):
                fname = m.group(1)
                params = m.group(2) or ""
                call_match = _CALL_RE.search(body)
                if not call_match:
                    continue
                kind = call_match.group(1)  # call | delegatecall

                fn = fn_index.get(fname)
                visibility = fn.visibility if fn else "unknown"
                if visibility not in ("public", "external", "unknown"):
                    continue
                guarded = fn.has_access_control if fn else False

                # Heuristic: is the call target / data derived from parameters?
                param_names = [
                    p.strip().split()[-1]
                    for p in params.split(",")
                    if p.strip() and len(p.strip().split()) >= 2
                ]
                user_controlled = any(pn and pn in body for pn in param_names)

                is_delegate = kind == "delegatecall"
                impact = 9.0 if is_delegate else 7.0
                confidence = 2.0
                if user_controlled:
                    confidence += 3.0
                if not guarded:
                    confidence += 2.0
                else:
                    impact -= 1.0  # guarded reduces practical impact

                severity = "info"
                if not guarded and user_controlled:
                    severity = "critical" if is_delegate else "high"
                elif user_controlled:
                    severity = "medium"

                findings.append(
                    FindingCandidate(
                        detector=self.name,
                        title=(
                            f"{'delegatecall' if is_delegate else 'low-level call'} "
                            f"in {visibility} function {fname}"
                        ),
                        description=(
                            f"`{fname}` performs a `{kind}`"
                            + (
                                " using values that appear parameter-controlled"
                                if user_controlled
                                else ""
                            )
                            + (
                                "; no access control detected."
                                if not guarded
                                else "; access control present."
                            )
                            + (
                                " delegatecall can execute arbitrary code in this "
                                "contract's storage context (proxy hijack / fund theft)."
                                if is_delegate
                                else ""
                            )
                        ),
                        impact_score=max(0.0, min(10.0, impact)),
                        confidence_score=max(0.0, min(10.0, confidence)),
                        severity_candidate=severity,
                        evidence={
                            "function": fname,
                            "kind": kind,
                            "visibility": visibility,
                            "has_access_control": guarded,
                            "user_controlled_target_or_data": user_controlled,
                            "params": params.strip(),
                            "file": path,
                            "snippet": body[:1200],
                        },
                        next_tests=[
                            f"Trace whether the {kind} target/data is attacker-controlled",
                            "Check for whitelist/allow-list on the target",
                            "Fork-simulate the call from an unprivileged account",
                        ],
                        affected_functions=[fname],
                    )
                )

        return findings
