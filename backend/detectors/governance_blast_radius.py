"""Detector: governance blast radius (Scroll-audit inspired, generic).

Combines:
  * which dangerous selectors the contract exposes,
  * who controls them (ProxyAdmin owner / Ownable owner / role holders),
  * whether a timelock delay applies (getMinDelay),
  * on-chain role probing (zero/dead address).

Classification philosophy (encoded via evidence flags consumed by scoring):
  * Governance can upgrade BY DESIGN  -> LOW_OR_INFO
  * No timelock delay but documented   -> LOW_OR_INFO / NEEDS_MORE_INVESTIGATION
  * Public/unexpected role or unguarded -> LIKELY_CRITICAL_NEEDS_POC
"""
from __future__ import annotations

from .base import (
    Detector,
    FindingCandidate,
    TargetContext,
    is_externally_callable,
    role_hash,
)

DANGEROUS_SELECTORS = {
    "upgrade",
    "upgradeTo",
    "upgradeAndCall",
    "upgradeToAndCall",
    "changeProxyAdmin",
    "transferOwnership",
    "renounceOwnership",
    "diamondCut",
    "setImplementation",
    "setPause",
    "pause",
    "unpause",
    "updateSigner",
    "updateMessageQueueParameters",
    "updateEnforcedBatchParameters",
    "addSequencer",
    "removeSequencer",
    "addProver",
    "removeProver",
}

ROLE_NAMES = [
    "DEFAULT_ADMIN_ROLE",
    "TIMELOCK_ADMIN_ROLE",
    "PROPOSER_ROLE",
    "EXECUTOR_ROLE",
    "CANCELLER_ROLE",
]
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD"


class GovernanceBlastRadiusDetector(Detector):
    name = "governance_blast_radius"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        proxy = ctx.proxy_info
        oc = ctx.onchain

        funcs = ctx.functions()
        abi_names = ctx.abi_function_names()
        present = {f.name for f in funcs} | abi_names
        dangerous_present = sorted(DANGEROUS_SELECTORS & present)
        if not dangerous_present:
            return findings

        # Controller picture from on-chain reads.
        min_delay = oc.get_min_delay(ctx.address) if oc.available else None
        controller = proxy.admin_owner or proxy.owner or proxy.admin
        has_controller = controller is not None
        has_timelock = bool(min_delay)

        # On-chain open-role probing.
        open_roles: dict[str, dict] = {}
        if oc.available:
            for rn in ROLE_NAMES:
                rh = role_hash(rn)
                z = oc.has_role(ctx.address, rh, ZERO_ADDRESS)
                d = oc.has_role(ctx.address, rh, DEAD_ADDRESS)
                if z or d:
                    open_roles[rn] = {"zero": z, "dead": d, "hash": "0x" + rh.hex()}

        # Map functions to whether they are guarded.
        guarded_map = {f.name: f.has_access_control for f in funcs}
        unguarded_dangerous = [
            name
            for name in dangerous_present
            for f in funcs
            if f.name == name and is_externally_callable(f) and not f.has_access_control
        ]
        unguarded_dangerous = sorted(set(unguarded_dangerous))

        base_evidence = {
            "address": ctx.address,
            "dangerous_selectors_present": dangerous_present,
            "controller": controller,
            "proxy_admin": proxy.admin,
            "proxy_admin_owner": proxy.admin_owner,
            "owner": proxy.owner,
            "min_delay_seconds": min_delay,
            "open_roles": open_roles,
            "guarded_map": guarded_map,
        }

        # --- Case 1: unguarded dangerous selector (source) -------------- #
        if unguarded_dangerous:
            findings.append(
                FindingCandidate(
                    detector=self.name,
                    title=f"Unguarded dangerous selector(s): {', '.join(unguarded_dangerous)}",
                    description=(
                        "Dangerous governance selectors appear externally callable with no "
                        "access-control modifier detected. If reachable, this is an "
                        "unauthorized-control candidate (needs PoC/fork confirmation)."
                    ),
                    impact_score=9.0,
                    confidence_score=6.0,
                    severity_candidate="critical",
                    evidence={**base_evidence, "unguarded": unguarded_dangerous},
                    next_tests=[
                        "Fork-call each unguarded selector from an unprivileged account",
                        "Confirm whether storage/funds change as a result",
                    ],
                    affected_functions=unguarded_dangerous,
                )
            )

        # --- Case 2: open role on-chain --------------------------------- #
        if open_roles:
            critical_open = {
                r for r in open_roles if r in ("DEFAULT_ADMIN_ROLE", "TIMELOCK_ADMIN_ROLE", "PROPOSER_ROLE")
            }
            findings.append(
                FindingCandidate(
                    detector=self.name,
                    title=f"Open governance role(s): {', '.join(open_roles)}",
                    description=(
                        "On-chain hasRole() shows governance role(s) held by the zero/dead "
                        "address while dangerous selectors exist. Potentially anyone-callable "
                        "privileged path."
                    ),
                    impact_score=9.0 if critical_open else 6.0,
                    confidence_score=7.0 if critical_open else 5.0,
                    severity_candidate="critical" if critical_open else "high",
                    evidence={**base_evidence, "open_roles": open_roles},
                    next_tests=[
                        "Confirm which dangerous selector each open role authorizes",
                        "Fork-execute a privileged action using the open role",
                    ],
                    affected_functions=sorted(open_roles),
                )
            )

        # --- Case 3: expected governance power (documented / guarded) --- #
        if not unguarded_dangerous and not open_roles:
            doc_note = (
                "Timelock delay present." if has_timelock else "No timelock delay observed."
            )
            findings.append(
                FindingCandidate(
                    detector=self.name,
                    title="Governance can perform privileged actions (by design)",
                    description=(
                        "Dangerous selectors exist but are access-controlled and/or owned by "
                        f"{controller or 'an owner/admin'}. {doc_note} This is governance "
                        "power, not automatically a bug. Verify the controller is the expected "
                        "timelock/multisig and the trust model is documented."
                    ),
                    impact_score=8.0,
                    confidence_score=2.0,
                    severity_candidate="low",
                    evidence={
                        **base_evidence,
                        "governance_controlled": True,
                        "documented_centralization": True,
                        "has_timelock": has_timelock,
                    },
                    next_tests=[
                        "Confirm controller is the expected timelock/multisig address",
                        "Check program scope: is centralization in-scope or excluded?",
                    ],
                    affected_functions=dangerous_present,
                )
            )

        return findings
