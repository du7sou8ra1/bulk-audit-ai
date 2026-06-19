"""Detector: arithmetic / mint-logic bugs (v0.4).

Maps to MakinaFi (overflow), Solv (double-mint race), Truebit (unauthorized mint).

  * `unchecked { ... }` blocks containing +/* on non-trivial expressions — the
    0.8 overflow guard is deliberately switched off there.
  * mint/credit functions with NO idempotency marker (no processed[..]=true /
    nonce / require(!claimed)) -> replayable double-mint.
  * mint/burn that is externally callable with no access-control modifier ->
    unauthorized mint (Truebit).
"""
from __future__ import annotations

import re

from .base import (
    Detector,
    FindingCandidate,
    TargetContext,
    header_has_access_control,
    iter_function_bodies,
)

_MINT_RE = re.compile(r"_mint\s*\(|\bmint\s*\(|_creditTo|increaseBalance|balances?\[[^\]]*\]\s*\+=",
                      re.IGNORECASE)
_IDEMPOTENT_RE = re.compile(
    r"(processed|claimed|used|minted|consumed|finalized|nonce|seen)[\w.]*\[[^\]]*\]\s*=\s*true"
    r"|require\s*\(\s*!?\s*[\w.]*(processed|claimed|used|minted|consumed)",
    re.IGNORECASE,
)
_UNCHECKED_RE = re.compile(r"unchecked\s*\{([^}]*)\}", re.IGNORECASE | re.DOTALL)
_RISKY_MATH_RE = re.compile(r"[\w.\])]\s*[+*]\s*[\w.(]")
_MINTISH_NAME = ("mint", "claim", "credit", "redeem", "reward", "distribute", "issue")


class ArithmeticLogicDetector(Detector):
    name = "arithmetic_logic"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, tail, body in iter_function_bodies(source):
                lname = fname.lower()
                guarded = header_has_access_control(tail)
                ext = re.search(r"\b(public|external)\b", tail) is not None

                # 1) unchecked arithmetic with real operations
                for um in _UNCHECKED_RE.finditer(body):
                    inner = um.group(1)
                    if _RISKY_MATH_RE.search(inner) and len(inner.strip()) > 12:
                        findings.append(self._c(
                            fname, path, body,
                            title=f"unchecked arithmetic on non-trivial expression: {fname}",
                            desc=(f"`{fname}` performs +/* inside an `unchecked` block, disabling "
                                  "Solidity 0.8 overflow protection. If any operand is user- or "
                                  "balance-influenced this can overflow/underflow (MakinaFi class)."),
                            impact=7.0, conf=4.0, bug="math",
                            tests=["Fuzz the operands to force overflow/underflow",
                                   "Confirm operands are provably bounded before the unchecked block"]))
                        break

                # 2) mint/credit without idempotency -> double-mint
                if any(k in lname for k in _MINTISH_NAME) and _MINT_RE.search(body):
                    if not _IDEMPOTENT_RE.search(body):
                        findings.append(self._c(
                            fname, path, body,
                            title=f"Mint/credit without idempotency marker: {fname}",
                            desc=(f"`{fname}` mints/credits value but no consumed/processed/nonce "
                                  "marker was found. If a request id can be reused (or two txs race) "
                                  "this is a double-mint (Solv class)."),
                            impact=8.5, conf=4.0, bug="double_mint",
                            tests=["Replay the same mint request twice on a fork; expect the 2nd to revert",
                                   "Confirm a per-request nonce/flag is set BEFORE the mint"]))

                # 3) externally callable mint/burn with no access control
                if ext and not guarded and re.search(r"\b(mint|burn)\b", lname):
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Externally callable mint/burn with no access control: {fname}",
                        desc=(f"`{fname}` is {('external/public')} and mint/burn-named but no "
                              "access-control modifier was detected — possible unauthorized "
                              "mint (Truebit class)."),
                        impact=9.0, conf=5.0, bug="access_control",
                        tests=["eth_call this function from a random EOA on a fork; expect revert if guarded"],
                        unprivileged=True))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, bug, tests, unprivileged=True):
        return FindingCandidate(
            detector="arithmetic_logic", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="critical" if impact >= 9 else "high",
            evidence={"function": fname, "file": path, "snippet": body[:1500],
                      "bug_class": bug, "needs_poc": True, "unprivileged": unprivileged},
            next_tests=tests, affected_functions=[fname],
        )
