"""Detector: cross-chain bridge accounting flaws (v0.2).

Heuristic source analysis for the classic bridge bug shapes:
  * failed-deposit recovery that does NOT clear deposit state  -> replay/double-spend
  * recovery that does NOT verify the deposit actually failed   -> forged recovery
  * withdrawal/message finalization with NO proof verification  -> finalization bypass
  * finalization with NO replay marking                         -> replay
  * external transfer BEFORE the replay mark (CEI violation)    -> reentrancy/replay

These are CANDIDATES (modest confidence) — real confirmation needs flow analysis
or a fork PoC. The detector first checks the contract is bridge-like to avoid
firing on ordinary tokens/vaults.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, strip_comments

_BRIDGE_MARKERS = (
    "bridge", "deposit", "withdraw", "finalize", "crosschain", "cross-chain",
    "relaymessage", "messenger", "portal", "l1", "l2", "outbox", "inbox",
)

_RECOVERY_NAMES = (
    "faileddeposit", "claimfailed", "recoverfailed", "refund", "claimrefund",
    "forcewithdraw", "finalizefailed", "canceldeposit",
)
_FINALIZE_NAMES = (
    "finalizewithdraw", "finalizemessage", "relaymessage", "executemessage",
    "finalizedeposit", "provewithdraw", "processmessage", "claimwithdrawal",
)

# A replay marker: a mapping/array element (incl. dotted/struct accessors)
# set to true, covering common names (finalized/processed/used/consumed/nonce…).
_MARK_RE = re.compile(
    r"(finalized|processed|executed|spent|claimed|relayed|completed|recorded|"
    r"used|consumed|nonces?|nonceused|seen)[\w.]*\s*\[[^\]]*\]\s*=\s*true",
    re.IGNORECASE,
)
_EXT_TRANSFER_RE = re.compile(
    r"\.\s*(call|transfer|send)\s*[({]|safeTransfer|sendValue|_transfer\s*\(",
    re.IGNORECASE,
)
_VERIFY_RE = re.compile(r"verify|proof|merkle|_verify|root|witness", re.IGNORECASE)
# Clearing deposit state: `delete x[...]` or `x[...] = 0/false`. Deliberately
# requires an indexed target so a plain `uint fee = 0;` does NOT count as a clear.
_CLEAR_RE = re.compile(
    r"\bdelete\s+[\w.]+\s*\[|[\w.]+\s*\[[^\]]*\]\s*=\s*(false|0)\b", re.IGNORECASE
)
# Verifying the deposit actually failed — match status-ish words, NOT the bare
# `success` bool returned by a low-level .call (which would mask the finding).
_FAILURE_CHECK_RE = re.compile(
    r"require\s*\([^)]*(status|failed|isfailed|hasfailed|notsuccess|!success)", re.IGNORECASE
)


def _iter_bodies(source: str):
    """Yield (function_name, body_text) for each braced function."""
    for m in re.finditer(r"function\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{", source):
        start = m.end() - 1
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
        yield m.group(1), source[start : i + 1]


class BridgeAccountingDetector(Detector):
    name = "bridge_accounting"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        src = ctx.all_source_text()
        if not src:
            return []
        low = src.lower()
        if sum(1 for mk in _BRIDGE_MARKERS if mk in low) < 2:
            return []  # not bridge-like; avoid false positives on plain tokens

        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            source = strip_comments(source)  # don't let comments trigger matches
            for fname, body in _iter_bodies(source):
                lname = fname.lower()
                snippet = body[:1500]

                # --- Failed-deposit recovery ------------------------------ #
                if any(k in lname for k in _RECOVERY_NAMES):
                    clears = bool(_CLEAR_RE.search(body))
                    verifies_failure = bool(_FAILURE_CHECK_RE.search(body))
                    binds = "msg.sender" in body or (
                        "keccak256" in body
                        and any(t in body.lower() for t in ("recipient", "amount", "to"))
                    )
                    if not clears:
                        findings.append(
                            self._cand(
                                fname, path, snippet,
                                title=f"Failed-deposit recovery does not clear state: {fname}",
                                desc=(
                                    f"`{fname}` looks like a failed-deposit recovery but no state "
                                    "clear (delete / set-to-zero) was detected. If the deposit "
                                    "record is not consumed, the recovery may be replayed for a "
                                    "double refund / double spend."
                                ),
                                impact=9.0, confidence=4.0,
                                extra={"clears_state": clears, "verifies_failure": verifies_failure,
                                       "binds_recipient_amount": binds},
                                tests=[
                                    "Confirm the deposit mapping is deleted/consumed on recovery",
                                    "Fork-replay the recovery twice and check for a double payout",
                                ],
                            )
                        )
                    elif not verifies_failure:
                        findings.append(
                            self._cand(
                                fname, path, snippet,
                                title=f"Recovery does not verify deposit failure: {fname}",
                                desc=(
                                    f"`{fname}` clears state but no explicit failure-status check "
                                    "was detected. A successful deposit might be 'recovered', "
                                    "letting an attacker reclaim already-bridged funds."
                                ),
                                impact=8.0, confidence=3.0,
                                extra={"clears_state": clears, "verifies_failure": verifies_failure},
                                tests=["Confirm the recovery requires a proven failure status"],
                            )
                        )

                # --- Withdrawal / message finalization -------------------- #
                if any(k in lname for k in _FINALIZE_NAMES):
                    verifies = bool(_VERIFY_RE.search(body))
                    mark_m = _MARK_RE.search(body)
                    ext_m = _EXT_TRANSFER_RE.search(body)
                    if not ext_m:
                        continue  # no value movement -> not an accounting risk here

                    if not verifies:
                        findings.append(
                            self._cand(
                                fname, path, snippet,
                                title=f"Finalization without proof verification: {fname}",
                                desc=(
                                    f"`{fname}` moves value but no proof/merkle/root verification "
                                    "was detected. If the message/withdrawal is not proven, an "
                                    "attacker may forge a finalization (withdrawal bypass)."
                                ),
                                impact=9.0, confidence=4.0,
                                extra={"has_verification": verifies, "has_replay_mark": bool(mark_m)},
                                tests=[
                                    "Confirm a merkle/proof check binds the message to a known root",
                                    "Fork-call finalize with a forged message and check it reverts",
                                ],
                            )
                        )
                    if not mark_m:
                        findings.append(
                            self._cand(
                                fname, path, snippet,
                                title=f"Finalization without replay protection: {fname}",
                                desc=(
                                    f"`{fname}` moves value but no replay marker "
                                    "(processed/finalized[...] = true) was detected. The "
                                    "withdrawal/message may be replayable for repeated payouts."
                                ),
                                impact=9.0, confidence=4.0,
                                extra={"has_verification": verifies, "has_replay_mark": bool(mark_m)},
                                tests=["Confirm the message id/nonce is marked consumed before payout"],
                            )
                        )
                    elif ext_m.start() < mark_m.start():
                        findings.append(
                            self._cand(
                                fname, path, snippet,
                                title=f"External transfer before replay mark (CEI): {fname}",
                                desc=(
                                    f"In `{fname}` the external value transfer appears BEFORE the "
                                    "replay marker is set. This violates checks-effects-interactions "
                                    "and may enable reentrancy / replay before state is updated."
                                ),
                                impact=8.0, confidence=4.0,
                                extra={"transfer_index": ext_m.start(), "mark_index": mark_m.start()},
                                tests=[
                                    "Confirm the replay marker is set BEFORE any external call",
                                    "Fork-reenter the finalize path during the external call",
                                ],
                            )
                        )
        return findings

    @staticmethod
    def _cand(fname, path, snippet, *, title, desc, impact, confidence, extra, tests):
        return FindingCandidate(
            detector="bridge_accounting",
            title=title,
            description=desc,
            impact_score=impact,
            confidence_score=confidence,
            severity_candidate="critical" if impact >= 9 else "high",
            evidence={"function": fname, "file": path, "snippet": snippet, **extra},
            next_tests=tests,
            affected_functions=[fname],
        )
