"""Adversarial refutation layer (gap #3).

The original pipeline only *triaged* candidates (one DeepSeek call that tends to
accept the detector's framing). The single most effective quality step in a real
audit is an INDEPENDENT skeptic that tries to DISPROVE each finding by reading the
actual code: the gating `require`, the binding invariant, the rounding that
actually favors the protocol, the hash-chain that binds caller data to a proof,
or plain economic infeasibility.

`refute()` runs before AI triage. A refuted finding is marked
`evidence["refuted"]=True` (+ reason); scoring then hard-caps its confidence so it
cannot reach a critical bucket. Survivors proceed to triage / PoC as before.
"""
from __future__ import annotations

import logging

from ..detectors.base import FindingCandidate, TargetContext
from .callgraph import CallGraph
from .llm import chat_json, llm_available

logger = logging.getLogger("bulkauditai.refuter")

_SYSTEM = """You are an adversarial smart-contract auditor. Your ONLY job is to try to
REFUTE the candidate finding below by reading the actual code slice provided.

Look hard for any reason it is NOT exploitable by an unprivileged actor:
- an access-control modifier / require that gates it,
- an invariant or hash/commitment that binds caller-supplied data to a proof or
  stored value (so it can't be forged),
- a require that blocks the bad amount (e.g. balance check, range check),
- rounding that actually rounds in the PROTOCOL's favor (deposit floors shares,
  withdraw floors assets),
- a nullifier/replay-marker set before the external call,
- economic infeasibility (needs a hash preimage, needs to BE a trusted role).

Default to is_real=false unless the exploit genuinely survives your scrutiny.
A finding that only relies on trusted owner/operator power is NOT a real
unprivileged bug -> is_real=false, in_scope=false.

Return ONLY JSON:
{"is_real": true|false,
 "refutation": "the single strongest argument AGAINST exploitability (cite the code)",
 "residual_severity": "critical|high|medium|low|info|none",
 "in_scope": true|false,
 "concrete_mitigation": true|false,
 "reasoning": "brief"}"""

# Appended for lead_only findings (binding may live off-chain / needs a fork PoC).
_LEAD_ADDENDUM = """

THIS CANDIDATE IS A LEAD: the detector has ALREADY determined it cannot be confirmed
from Solidity alone — the binding may live in the off-chain circuit, or confirming it
needs a fork PoC. Therefore "I cannot confirm it", "it depends on the circuit",
"needs a PoC", or "the proof probably constrains it" are NOT refutations — they are
the EXPECTED state of this finding and must NOT, on their own, set is_real=false.
You may treat the lead as defused ONLY when you can cite a CONCRETE on-chain control
present in the slice that actually neutralizes it: an equality/range require binding
the value or count to the proof-committed quantity, a hash-compare against a
committed value, or an access modifier blocking unprivileged callers. If no such
concrete control exists, the lead SURVIVES for human / circuit investigation.
Set "concrete_mitigation": true ONLY if you cited such a control; otherwise false."""


def refute(ctx: TargetContext, candidate: FindingCandidate, cg: CallGraph | None = None) -> dict:
    """Returns a verdict dict; also mutates candidate.evidence with the result."""
    verdict = {"attempted": False, "is_real": None, "refutation": "", "in_scope": None}
    if not llm_available():
        candidate.evidence.setdefault("refutation", {"attempted": False, "reason": "llm unavailable"})
        return verdict

    ev0 = candidate.evidence or {}
    is_lead = bool(ev0.get("lead_only") or ev0.get("onchain_detectable") == "lead_only")
    system = _SYSTEM + (_LEAD_ADDENDUM if is_lead else "")

    cg = cg or CallGraph.build(ctx.source_files)
    fn = (candidate.affected_functions or [None])[0]
    code_slice = cg.slice_for(fn) if fn else ""
    if not code_slice:
        # Fall back to the candidate's own snippet so the skeptic still has code.
        code_slice = str((candidate.evidence or {}).get("snippet", ""))[:6000]

    payload = {
        "candidate": {
            "title": candidate.title,
            "detector": candidate.detector,
            "severity": candidate.severity_candidate,
            "function": fn,
            "claim": candidate.description,
            "bug_class": (candidate.evidence or {}).get("bug_class"),
        },
        "contract": ctx.contract_name or ctx.address,
        "code_slice": code_slice,
    }
    res = chat_json(system, payload, timeout=180)
    if res.error or not res.parsed:
        candidate.evidence.setdefault("refutation", {"attempted": True, "error": res.error})
        return {**verdict, "attempted": True, "error": res.error}

    p = res.parsed
    is_real = bool(p.get("is_real", True))
    in_scope = bool(p.get("in_scope", True))
    refutation = str(p.get("refutation", ""))[:2000]
    residual = str(p.get("residual_severity", "")).lower()
    concrete = bool(p.get("concrete_mitigation", False))

    candidate.evidence["refutation"] = {
        "attempted": True,
        "is_real": is_real,
        "in_scope": in_scope,
        "residual_severity": residual,
        "concrete_mitigation": concrete,
        "refutation": refutation,
        "reasoning": str(p.get("reasoning", ""))[:1500],
    }
    # A finding the skeptic killed is flagged so scoring caps it hard. A LEAD is
    # only killed by a CITED on-chain control — never by "can't confirm" (that is
    # its expected state). Non-leads keep the original is_real/in_scope/residual gate.
    if is_lead:
        if concrete:
            candidate.evidence["refuted"] = True
            candidate.evidence["refuted_concrete"] = True
    elif (not is_real) or (not in_scope) or residual in ("none", "info"):
        candidate.evidence["refuted"] = True

    return {
        "attempted": True,
        "is_real": is_real,
        "in_scope": in_scope,
        "residual_severity": residual,
        "refutation": refutation,
    }
