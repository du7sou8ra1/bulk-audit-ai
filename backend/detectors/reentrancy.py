"""Detector: reentrancy / checks-effects-interactions violations (v0.5).

v0.5 adds INTERPROCEDURAL CEI. The external interaction is frequently NOT in the
function that writes state — it sits in a helper one or more call-hops away
(`doTransferOut`, `_safeTransfer`, `_sendValue`, ...). The v0.4 single-body regex
searched one function body for `.call{}` and so produced NOTHING for the
Rari/Fuse CEther reentrancy, where:

    borrowFresh(...) { doTransferOut(borrower, amt); accountBorrows[...] = ...; }
    doTransferOut(...) { to.call{value: amt}(""); }   // the external call lives HERE

We now build the call graph, mark every function that *reaches* an external call
through its callees (fixpoint), and treat a call to such a helper as an
interaction point. A state write after that point -> checks-effects-interactions
violation, even across function boundaries.

Maps to Venus (cross-function) + Rari/Fuse (external send via internal helper) +
read-only / cross-contract reentrancy. Candidates only; a confirm needs a fork
reentrancy PoC.
"""
from __future__ import annotations

import re

from ..core.callgraph import CallGraph
from .base import Detector, FindingCandidate, TargetContext

# A direct external interaction (control can leave the contract here).
_EXT_CALL_RE = re.compile(
    r"\.call\s*\{|\.call\s*\(|\.delegatecall\s*\(|safeTransfer(From)?\s*\(|"
    r"\.transfer\s*\(|\.send\s*\(|\.transferFrom\s*\(|\.onERC|\.tokensReceived",
    re.IGNORECASE,
)
# A persistent-state effect: mapping/array(+.field) write, or a named state var.
_STATE_WRITE_RE = re.compile(
    r"[A-Za-z_]\w*(?:\s*\[[^\]]*\])+(?:\s*\.\w+)*\s*(?:[+\-*/]?=)(?!=)|"
    r"\b(?:balances?|totalSupply|reserves?|totalBorrows?|exchangeRate|shares?|"
    r"pending\w*|accrued\w*|accountBorrows?|accountTokens?|principal|borrowIndex|"
    r"deposits?|debt|collateral)\b\s*(?:[+\-]?=)(?!=)",
    re.IGNORECASE,
)
_NONREENTRANT_RE = re.compile(
    r"nonReentrant|noReentr|reentrancyGuard|_status|_notEntered|lock\b", re.IGNORECASE
)


class ReentrancyDetector(Detector):
    name = "reentrancy"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        g = CallGraph.build(ctx.source_files)
        if not g.fns:
            return findings

        # 1) Seeds: functions that DIRECTLY perform an external call/transfer.
        reaches_ext: set[str] = {
            name for name, n in g.fns.items() if _EXT_CALL_RE.search(n.body)
        }
        # 2) Fixpoint: a function reaches-external if any callee reaches-external.
        changed, iters = True, 0
        while changed and iters < 16:
            changed, iters = False, iters + 1
            for name, n in g.fns.items():
                if name in reaches_ext:
                    continue
                if n.calls & reaches_ext:
                    reaches_ext.add(name)
                    changed = True

        for name, n in g.fns.items():
            tail = n.header_tail.lower()
            if "view" in tail or "pure" in tail:
                continue
            body = n.body

            # Earliest interaction point in this body: a direct external call,
            # or a call to a helper that (transitively) makes one.
            best: tuple[int, int, str, str | None] | None = None
            m = _EXT_CALL_RE.search(body)
            if m:
                best = (m.start(), m.end(), "direct", None)
            for callee in n.calls:
                if callee == name or callee not in reaches_ext:
                    continue
                cm = re.search(r"\b" + re.escape(callee) + r"\s*\(", body)
                if not cm:
                    continue
                if best is None or cm.start() < best[0]:
                    best = (cm.start(), cm.end(), "interprocedural", callee)
            if best is None:
                continue

            # A state effect AFTER the interaction => CEI violation.
            if not _STATE_WRITE_RE.search(body[best[1]:]):
                continue

            own_guard = bool(
                _NONREENTRANT_RE.search(n.header_tail) or _NONREENTRANT_RE.search(body[:200])
            )
            entry_guard = False
            if not own_guard:
                for caller in g.callers.get(name, ()):
                    cn = g.fns.get(caller)
                    if cn and (
                        _NONREENTRANT_RE.search(cn.header_tail)
                        or _NONREENTRANT_RE.search(cn.body[:200])
                    ):
                        entry_guard = True
                        break

            kind, callee = best[2], best[3]
            if own_guard:
                impact, conf = 5.0, 2.5
            elif entry_guard:
                # entry-point lock does NOT protect re-entry into a *different*
                # contract's state (the Rari/Fuse cross-contract case).
                impact, conf = 7.5, 4.5
            else:
                impact, conf = 9.0, 6.0

            if kind == "interprocedural":
                title = (
                    f"Cross-function reentrancy: state written after external call "
                    f"reached via `{callee}()` in {name}"
                )
                desc = (
                    f"In `{name}` a state write happens after a call to `{callee}()`, which "
                    f"(directly or transitively) performs an external call/transfer. The "
                    f"external interaction is not in `{name}` itself, so a single-function "
                    f"checks-effects-interactions scan misses it. If the called address is "
                    f"attacker-controlled (ERC777/ERC721 hook, low-level call, malicious "
                    f"token, or a re-enterable foreign contract), it can re-enter before "
                    f"state settles — the Rari/Fuse CEther class (borrowFresh -> doTransferOut)."
                )
            else:
                title = (
                    f"External call before state update"
                    f"{'' if own_guard else ' (no nonReentrant)'}: {name}"
                )
                desc = (
                    f"In `{name}` an external call/transfer occurs before a state write "
                    f"(checks-effects-interactions violation)"
                    f"{'' if own_guard else ' and no nonReentrant guard was found'}. "
                    f"If the called address is attacker-controlled it can re-enter this or a "
                    f"related function before state is settled."
                )
            if entry_guard and not own_guard:
                desc += (
                    " NOTE: a caller carries a reentrancy lock, but that lock does not cover "
                    "re-entry into other contracts' state (cross-contract / read-only reentrancy)."
                )

            findings.append(FindingCandidate(
                detector="reentrancy",
                title=title,
                description=desc,
                impact_score=impact, confidence_score=conf,
                severity_candidate=("critical" if impact >= 9 else "high" if impact >= 7 else "medium"),
                evidence={
                    "function": name, "file": n.file, "snippet": body[:1500],
                    "bug_class": "reentrancy", "needs_poc": True, "unprivileged": True,
                    "has_guard": own_guard, "entry_guarded": entry_guard,
                    "interprocedural": kind == "interprocedural", "via_callee": callee,
                },
                next_tests=[
                    "Fork-deploy a malicious token/receiver that re-enters during the external call",
                    "Confirm all state effects happen BEFORE the external interaction (CEI)",
                    "Check the reentrancy lock (if any) covers EVERY function and foreign contract re-entered",
                ],
                affected_functions=[name],
            ))
        return findings
