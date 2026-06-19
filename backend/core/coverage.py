"""Per-target coverage accounting (gap #6).

"0 findings" must never silently read as "safe". A bulk auditor has to know
*what was actually examined* vs. *what was skipped or is structurally out of
tool scope*. This builds a compact coverage report per target that is written to
the workspace and surfaced to the UI, so a clean result is honestly scoped.
"""
from __future__ import annotations

from ..detectors.base import TargetContext
from .callgraph import CallGraph

# Heuristic surface fingerprints -> the surface name and which detector(s) cover it.
_SURFACE_HINTS = {
    "share_accounting": (("deposit", "withdraw", "redeem", "totalassets", "convertto", "pricepershare"),
                         ("invariant_reasoner",)),
    "settlement_proof_binding": (("executebatch", "verifybatch", "commitbatch", "onchainoperations",
                                  "provewithdraw", "finalizewithdraw"), ("invariant_reasoner", "bridge_accounting")),
    "bridge_messaging": (("relaymessage", "finalizemessage", "l1tol2", "l2tol1", "outbox", "inbox"),
                         ("bridge_accounting",)),
    "access_control": (("onlyowner", "onlyrole", "requiresauth", "accesscontrol", "hasrole"),
                       ("timelock_roles", "governance_blast_radius", "access_control")),
    "proxy_upgrade": (("upgradeto", "_authorizeupgrade", "implementation", "initialize"),
                      ("proxy_upgrade",)),
    "signatures_permit": (("permit", "ecrecover", "eip712", "domainseparator"), ("permit_misuse",)),
    "zk_verifier": (("verifyproof", "snark", "groth16", "plonk", "verifier.verify", "desert"),
                    ("zk_verifier", "invariant_reasoner")),
    "swap_oracle": (("getrate", "latestanswer", "swap", "slippage", "minout", "oracle"),
                    ("invariant_reasoner",)),
}


def build_coverage(
    ctx: TargetContext,
    *,
    detectors_run: list[str],
    tool_statuses: dict[str, str],
    candidate_count: int,
    source_verified: bool,
    reasoner_meta: dict | None,
) -> dict:
    text = (ctx.all_source_text() or "").lower()
    cg = CallGraph.build(ctx.source_files) if ctx.source_files else None
    detectors_run_set = set(detectors_run)

    examined: list[str] = []
    gaps: list[str] = []
    for surface, (hints, cover_detectors) in _SURFACE_HINTS.items():
        present = sum(1 for h in hints if h in text) >= 2
        if not present:
            continue
        covered = bool(detectors_run_set & set(cover_detectors))
        (examined if covered else gaps).append(surface)

    # ZK honesty: if proof-verification surface is present, the off-chain circuit
    # is structurally OUT of this tool's reach — say so explicitly.
    is_zk = any(k in text for k in ("verifyproof", "snark", "groth16", "plonk", "desertverifier", ".verify("))
    out_of_tool_scope: list[str] = []
    if is_zk:
        out_of_tool_scope.append(
            "off-chain ZK circuit / proving system (boojum/halo2/circom/plonk) — "
            "soundness bugs live here and are NOT visible to a Solidity-only tool; "
            "needs a ZK specialist. Only the on-chain settlement<->proof binding was assessed."
        )

    if not source_verified:
        out_of_tool_scope.append("contract source not verified — only bytecode/on-chain checks ran")

    skipped_tools = [t for t, st in tool_statuses.items() if st in ("skipped", "failed", "timeout")]

    n_ext = len(cg.state_changing_externals()) if cg else 0
    reasoner_ok = bool(reasoner_meta and reasoner_meta.get("functions_examined"))

    honest = (
        f"Examined surfaces: {', '.join(examined) or 'none matched'}. "
        f"Detectors run: {', '.join(sorted(detectors_run_set)) or 'none'}. "
        f"{'Semantic invariant reasoning ran on '+str(len(reasoner_meta.get('functions_examined',[])))+' value-moving functions. ' if reasoner_ok else 'Semantic reasoning did NOT run (LLM off or no source). '}"
        f"State-changing external functions in scope: {n_ext}. "
        f"{('NOT covered (no detector fired for): '+', '.join(gaps)+'. ') if gaps else ''}"
        f"{('Out of tool scope: '+'; '.join(out_of_tool_scope)+'. ') if out_of_tool_scope else ''}"
        f"{candidate_count} candidate(s) produced. "
        "A clean result means these surfaces were checked — not that unlisted surfaces are safe."
    )

    return {
        "surfaces_examined": examined,
        "surfaces_with_no_detector": gaps,
        "out_of_tool_scope": out_of_tool_scope,
        "detectors_run": sorted(detectors_run_set),
        "tools_skipped_or_failed": skipped_tools,
        "semantic_reasoning_ran": reasoner_ok,
        "state_changing_externals": n_ext,
        "source_verified": source_verified,
        "candidate_count": candidate_count,
        "honest_summary": honest,
    }
