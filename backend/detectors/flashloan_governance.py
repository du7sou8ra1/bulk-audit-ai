"""Detector: flash-loanable governance (v0.5) -- the Beanstalk class.

Beanstalk lost ~$182M in ONE transaction because two properties held at once:
  * voting power was read from a SPOT balance/deposit at call time (no snapshot /
    checkpoint), so a flash loan instantly bought a controlling stake, and
  * a proposal could be executed in the same transaction (`emergencyCommit`) and
    that execution ran arbitrary code (`delegatecall` to a proposal `init`).

Either property alone is common and usually fine; TOGETHER they are the
flash-loan governance takeover. We require BOTH signals to fire, which keeps
snapshot-based governors (Compound/OZ `getPastVotes`) and plain weighted polls
out of the results. Candidate only; confirm with a fork flash-loan vote PoC.
"""
from __future__ import annotations

import re

from ..core.callgraph import CallGraph
from .base import Detector, FindingCandidate, TargetContext

_VOTE_RE = re.compile(r"\b(vote|castVote|propose|commit|tally|quorum)\b", re.IGNORECASE)
_SPOT_BALANCE_RE = re.compile(
    r"balanceOf\w*\s*\(|votingPower\s*\(|getVotes\s*\(|deposited\s*\(|"
    r"stakedBalance|balanceOfStalk|balanceOfRoots|\.balanceOf\b",
    re.IGNORECASE,
)
# Snapshot / checkpoint APIs that make a flash loan useless.
_SNAPSHOT_RE = re.compile(
    r"getPastVotes|getPriorVotes|getPastTotalSupply|getPriorBalance|balanceOfAt|"
    r"totalSupplyAt|_checkpoint|writeCheckpoint|snapshot",
    re.IGNORECASE,
)
_EMERGENCY_RE = re.compile(r"emergencyCommit|emergencyExecute|emergencyProcess|forceCommit", re.IGNORECASE)
_ARBEXEC_RE = re.compile(
    r"\.delegatecall\s*\(|functionDelegateCall|diamondCut|_delegatecall\s*\(", re.IGNORECASE
)
_EXEC_NAME_RE = re.compile(r"(execute|commit|process)", re.IGNORECASE)


class FlashloanGovernanceDetector(Detector):
    name = "flashloan_governance"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        g = CallGraph.build(ctx.source_files)
        if not g.fns:
            return []
        all_src = ctx.all_source_text()

        has_vote = any(_VOTE_RE.search(name) for name in g.fns) or bool(
            re.search(r"\b(quorum|votingPower|proposal|ballot|bip)\b", all_src, re.IGNORECASE)
        )
        uses_spot = bool(_SPOT_BALANCE_RE.search(all_src))
        uses_snapshot = bool(_SNAPSHOT_RE.search(all_src))
        spot_power = has_vote and uses_spot and not uses_snapshot

        emergency_fns = [name for name in g.fns if _EMERGENCY_RE.search(name)]
        arbexec_fns = [
            name for name, n in g.fns.items()
            if _EXEC_NAME_RE.search(name) and _ARBEXEC_RE.search(n.body)
        ]
        exec_fns = emergency_fns or arbexec_fns
        exec_risk = bool(exec_fns)

        if not (spot_power and exec_risk):
            return []

        vote_fns = [name for name in g.fns if _VOTE_RE.search(name)]
        affected = list(dict.fromkeys(vote_fns + exec_fns))[:6]
        why_exec = (
            "an `emergencyCommit`-style path executes in the SAME transaction"
            if emergency_fns else
            "the execution path runs arbitrary code via delegatecall/diamondCut"
        )
        return [FindingCandidate(
            detector="flashloan_governance",
            title="Flash-loanable governance: spot-balance voting power + same-tx/arbitrary execution",
            description=(
                "Voting power is derived from a spot balance/deposit read at call time "
                "(no snapshot/checkpoint API such as getPastVotes/balanceOfAt was found), and "
                f"{why_exec}. An attacker can flash-loan the governance token, vote a malicious "
                "proposal through, execute it, and repay -- all atomically. This is the Beanstalk "
                "governance takeover ($182M, one transaction)."
            ),
            impact_score=9.0, confidence_score=6.0,
            severity_candidate="critical",
            evidence={
                "bug_class": "governance_flashloan", "needs_poc": True, "unprivileged": True,
                "spot_power": True, "snapshot_protected": uses_snapshot,
                "emergency_exec": bool(emergency_fns), "arbitrary_exec": bool(arbexec_fns),
                "vote_functions": vote_fns[:8], "exec_functions": exec_fns[:8],
            },
            next_tests=[
                "On a fork, flash-loan the governance token and call the vote/commit path",
                "Pass a malicious proposal and execute it in the same tx; confirm state change + repay",
                "Verify there is no snapshot (getPastVotes/balanceOfAt) and no timelock between vote and execute",
            ],
            affected_functions=affected,
        )]
