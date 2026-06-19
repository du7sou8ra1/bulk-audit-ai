"""Detector: ERC-2612 permit() misuse patterns.

Looks for code that calls ``permit(owner, msg.sender, ...)`` (or grants an
allowance to ``msg.sender``) and then pulls funds — a shape that, combined with
front-running of a victim's signature, can let an attacker redirect an approved
allowance. This is a heuristic candidate; it needs flow analysis / PoC.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, strip_comments

# permit(owner, spender, value, deadline, v, r, s) where spender == msg.sender
_PERMIT_MSG_SENDER = re.compile(
    r"permit\s*\(\s*([A-Za-z_]\w*)\s*,\s*msg\.sender", re.MULTILINE
)
# generic permit usage
_PERMIT_ANY = re.compile(r"\.?permit\s*\(", re.MULTILINE)
# transferFrom(owner, ..., ) right after permit
_TRANSFER_FROM = re.compile(r"transferFrom\s*\(", re.MULTILINE)


class PermitMisuseDetector(Detector):
    name = "permit_misuse"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        for path, source in ctx.source_files.items():
            if not source or "permit" not in source:
                continue
            source = strip_comments(source)  # ignore permit() mentions in comments
            if "permit" not in source:
                continue

            for m in _PERMIT_MSG_SENDER.finditer(source):
                owner_arg = m.group(1)
                line = source.count("\n", 0, m.start()) + 1
                window = source[max(0, m.start() - 200) : m.start() + 400]
                pulls_funds = bool(_TRANSFER_FROM.search(window))

                findings.append(
                    FindingCandidate(
                        detector=self.name,
                        title="permit(owner, msg.sender, ...) — allowance to caller",
                        description=(
                            f"Source calls permit() granting an allowance from `{owner_arg}` "
                            "to `msg.sender`. If the owner's signature can be front-run or the "
                            "approved allowance reused outside the intended flow, an attacker "
                            "may redirect funds. "
                            + (
                                "A transferFrom() follows nearby, increasing concern."
                                if pulls_funds
                                else "No adjacent transferFrom() found."
                            )
                        ),
                        impact_score=8.0 if pulls_funds else 6.0,
                        confidence_score=4.0 if pulls_funds else 3.0,
                        severity_candidate="high" if pulls_funds else "medium",
                        evidence={
                            "file": path,
                            "line": line,
                            "owner_arg": owner_arg,
                            "transfer_from_nearby": pulls_funds,
                            "snippet": window,
                        },
                        next_tests=[
                            "Check whether the permit signature binds the intended spender/recipient",
                            "Determine if a front-run permit can grant the attacker the allowance",
                            "Fork-simulate the permit + transferFrom path with an attacker spender",
                        ],
                        affected_functions=["permit"],
                    )
                )

            # Weaker signal: permit used at all alongside transferFrom but not the
            # msg.sender pattern — emit a low/info note once per file.
            if not _PERMIT_MSG_SENDER.search(source) and _PERMIT_ANY.search(source):
                if _TRANSFER_FROM.search(source):
                    findings.append(
                        FindingCandidate(
                            detector=self.name,
                            title="permit() + transferFrom present (review allowance flow)",
                            description=(
                                "Contract uses permit() and transferFrom(). Verify the "
                                "spender is bound correctly and signatures cannot be replayed "
                                "or redirected. Informational unless a misbinding is found."
                            ),
                            impact_score=5.0,
                            confidence_score=2.0,
                            severity_candidate="info",
                            evidence={"file": path},
                            next_tests=[
                                "Review who the permit spender is and whether it is attacker-settable"
                            ],
                            affected_functions=["permit"],
                        )
                    )

        return findings
