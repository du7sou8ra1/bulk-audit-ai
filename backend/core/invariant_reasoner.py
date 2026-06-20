"""Semantic invariant reasoner (gap #1).

The regex detectors surface shallow, name-based candidates and cannot follow a
cross-function invariant (e.g. "the withdrawal pubdata is bound to the verified
commitment via onChainOperationsHash", or "share price = oracle, not
totalAssets/supply, so donation can't move it"). This module hands the LLM a
call-graph-aware slice of the contract's value-moving functions and asks it to:

  1. build the accounting / trust model + invariants, and
  2. emit *hypotheses* (candidate findings) for invariant breaks an UNPRIVILEGED
     actor could exploit — rounding direction, share-price manipulation,
     settlement-vs-proof mismatch, missing replay/nullifier, reentrancy ordering,
     decimal scaling, etc.

These are CANDIDATES. They enter the same score -> refute -> AI-triage pipeline
as every other finding; the reasoner never confirms anything on its own.
"""
from __future__ import annotations

import logging

from ..detectors.base import FindingCandidate, TargetContext
from .callgraph import CallGraph
from .llm import chat_json, llm_available

logger = logging.getLogger("bulkauditai.invariant_reasoner")

# Functions whose name suggests they move value / change accounting — the slices
# we prioritise feeding to the model (bounded for cost).
_VALUE_MOVING_HINTS = (
    "deposit", "withdraw", "redeem", "mint", "burn", "claim", "exit", "swap",
    "transfer", "finalize", "execute", "settle", "liquidate", "borrow", "repay",
    "stake", "unstake", "rebalance", "harvest", "collect", "fulfill", "process",
    "provedesert", "performdesert", "relaymessage", "unshield", "perform",
)

_SYSTEM = """You are a senior smart-contract auditor doing INVARIANT-level reasoning.
You are given call-graph slices (a function plus its callees/callers and the state
variables it touches) from one contract/protocol. Reason about CROSS-FUNCTION
invariants, not single-line patterns.

First build the model, then hunt. Focus ONLY on issues an UNPRIVILEGED external
actor could exploit for fund loss/lock/theft or broken accounting. Treat
owner/governance/operator-only powers as NOT bugs (note them as trust assumptions).

Bug classes to weigh explicitly (report only if genuinely plausible in THIS code):
- share-price / accounting: is price = totalAssets/totalSupply (donation/inflation
  exposed) or an oracle (decoupled)? rounding direction on deposit vs withdraw —
  does any path round in the USER's favor? first-depositor inflation.
- settlement-vs-proof: does the contract act on caller-supplied data (withdrawal
  pubdata, amounts, recipients) that is NOT bound to a verified proof/commitment/hash?
- replay/nullifier: is the nullifier/processed-marker keyed to the SAME value the
  proof binds, and set before external calls (CEI)?
- decimal/precision scaling that mis-prices across token decimals.
- reentrancy via external call before state effect (only if a real cross-fn path).

ZK FORCED-EXIT / SETTLEMENT BINDING (give this special attention on any
escapeHatch/forcedExit/desert/withdraw/executeBatch path): do NOT treat the
presence of a verify()/verifyProof()/require(proof_verified) call as evidence the
release is safe — the Aztec 17 Jun 2026 drain (1,158 ETH) had a working verify().
For every value-releasing sink (.transfer, .call{value:}, _mint, safeTransfer,
increaseBalanceToWithdraw, _credit), name the exact symbol that determines (a) the
AMOUNT, (b) the RECIPIENT, (c) any FEE/relayer cut, (d) the ASSET/pool. For each,
decide: is it a caller-chosen parameter / calldata-struct field, or is it
re-derived from on-chain verified state (storage keyed by a proof-committed
commitment/nullifier, or a value re-hashed into the public-input vector that
verify() checked)? It is BOUND only if it appears inside the public-input array /
abi.encode(Packed) preimage / commitment passed to verify() (possibly via a helper
like createExitCommitment/_verifyPubdata whose result flows into that array) OR is
read from storage indexed by a proof-derived key. A single-element public-input
vector that omits the amount or recipient is a strong UNBINDING signal. Also check:
is the nullifier/proofId marked consumed BEFORE the release (replay), keyed over
asset/denomination (cross-asset replay), and could a committed-but-unproven root be
anchored by this withdrawal (commit/prove decoupling)? Conclude each release as
BOUND (cite the commitment field), UNBOUND-LEAD (cite the free param + absent
constraint), or REQUIRES-CIRCUIT (binding could only exist in public-input layout
you cannot see) — emit UNBOUND-LEAD as a settlement_binding hypothesis.

ZK SETTLEMENT-BOUNDARY / COUNT MISMATCH (the Aztec Connect $2.19M class — hunt this
explicitly on processRollup/processBatch/executeBatch/decodeProof/settle paths):
a count/length/size/index decoded from caller calldata (numTxs, numRealTxs,
rollupSize, numInnerRollups, batchSize, numBlocks, a loop bound) is used to bound
the L1 settlement loop, WHILE a SEPARATE, often larger/fixed range is what the ZK
proof commits to (the sha256/keccak public-inputs hash over the full slot range).
If there is no on-chain `require(callerCount == provenCount)` AND the gap slots
beyond the processed range are not forced to a safe value, the proof and the L1
loop interpret the same calldata differently: proof-committed slots go unprocessed/
unvalidated on L1, minting unbacked balances. Concretely check: which variable
bounds the settlement loop? is it the SAME quantity the proof/publicInputsHash
commits to, or a smaller caller-chosen count? is there any equality check between
them? Emit this as a settlement_binding hypothesis at HIGH severity when the
equality check is absent — do NOT down-rate it just because verify() is present and
the data is hashed; the hash covers the full range, the loop does not. Treat
"value/count read from proofData via extract*/abi.decode and used in settlement or
release, with no recompute-and-compare to the committed hash IN THE SAME PATH" as a
first-class lead, not an afterthought.

Return ONLY JSON:
{
 "model": {"accounting": "...", "trust": "...", "invariants": ["..."]},
 "hypotheses": [
   {"title":"...","bug_class":"share_accounting|settlement_binding|replay|reentrancy|oracle|decimal|other",
    "function":"<fn name>","severity":"critical|high|medium|low",
    "exploit_sketch":"concrete step-by-step OR why-impactful",
    "unprivileged":true|false,"confidence":0-10,
    "what_would_confirm":"the read-only/fork test that confirms or refutes"}
 ]
}
If the contract is sound for these classes, return an empty hypotheses array. Do NOT pad."""


def _select_functions(cg: CallGraph) -> list[str]:
    ranked: list[tuple[int, str]] = []
    for n in cg.state_changing_externals():
        low = n.name.lower()
        score = sum(1 for h in _VALUE_MOVING_HINTS if h in low)
        # value-moving + actually touches state vars => higher priority
        score += 1 if n.state_reads_writes else 0
        if score > 0:
            ranked.append((score, n.name))
    ranked.sort(reverse=True)
    return [name for _, name in ranked[:8]]


def _to_candidates(parsed: dict, model: dict) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    for h in parsed.get("hypotheses", []) or []:
        if not isinstance(h, dict):
            continue
        sev = str(h.get("severity", "medium")).lower()
        impact = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0}.get(sev, 5.0)
        # Hypotheses are unconfirmed: cap confidence so they MUST pass refutation
        # + AI triage (and ideally a PoC) before reaching CONFIRMED_CRITICAL.
        try:
            conf = float(h.get("confidence", 4))
        except (TypeError, ValueError):
            conf = 4.0
        conf = min(conf, 6.0)
        fn = str(h.get("function", "")) or None
        bug_class = str(h.get("bug_class", "other"))
        # Settlement/proof-binding hypotheses are unconfirmable from Solidity alone
        # (the binding lives in the circuit / needs a fork PoC) — tag them lead_only
        # so the pipeline keeps them at investigation level instead of letting the
        # refuter/classifier bury them as FALSE_POSITIVE (the Aztec failure mode).
        is_lead_class = any(
            t in bug_class.lower()
            for t in ("settlement", "binding", "boundary", "proof", "replay")
        )
        evidence = {
            "source": "invariant_reasoner",
            "bug_class": bug_class,
            "unprivileged": bool(h.get("unprivileged", False)),
            # NOTE: governance_controlled flips scoring's -3; set when the
            # model itself says this is NOT unprivileged.
            "governance_controlled": not bool(h.get("unprivileged", True)),
            "model_invariants": (model or {}).get("invariants", []),
            "needs_poc": True,
        }
        if is_lead_class:
            evidence["lead_only"] = True
            evidence["onchain_detectable"] = "lead_only"
        out.append(
            FindingCandidate(
                detector="invariant_reasoner",
                title=str(h.get("title", "Invariant hypothesis"))[:200],
                description=str(h.get("exploit_sketch", ""))[:4000],
                impact_score=impact,
                confidence_score=conf,
                severity_candidate=sev if sev in ("critical", "high", "medium", "low") else "medium",
                evidence=evidence,
                next_tests=[str(h.get("what_would_confirm", ""))][:1] or [],
                affected_functions=[fn] if fn else [],
            )
        )
    return out


def run_invariant_reasoner(ctx: TargetContext) -> tuple[list[FindingCandidate], dict]:
    """Returns (candidates, model). model is persisted as recon context."""
    if not llm_available():
        return [], {"skipped": "llm unavailable"}
    if not ctx.source_files:
        return [], {"skipped": "no source"}

    cg = CallGraph.build(ctx.source_files)
    fn_names = _select_functions(cg)
    if not fn_names:
        return [], {"skipped": "no value-moving external functions found"}

    slices = []
    for name in fn_names:
        sl = cg.slice_for(name)
        if sl:
            slices.append(sl)
    if not slices:
        return [], {"skipped": "no usable slices"}

    payload = {
        "contract": ctx.contract_name or ctx.address,
        "address": ctx.address,
        "chain": ctx.chain,
        "is_proxy": getattr(ctx.proxy_info, "is_proxy", False),
        "value_moving_functions": fn_names,
        "state_variables": sorted(list(cg.state_vars))[:120],
        "callgraph_slices": slices,
    }
    res = chat_json(_SYSTEM, payload, timeout=240)
    if res.error or not res.parsed:
        logger.info("invariant reasoner: %s", res.error)
        return [], {"error": res.error, "raw": res.raw_content[:1000]}

    model = res.parsed.get("model", {}) if isinstance(res.parsed, dict) else {}
    candidates = _to_candidates(res.parsed, model)
    return candidates, {"model": model, "functions_examined": fn_names}
