"""Detector: timelock / AccessControl role exposure (on-chain reads).

Checks the canonical OpenZeppelin role hashes against the zero address and a
"dead" address using read-only ``hasRole`` calls, plus ``getMinDelay`` for
timelocks. Open PROPOSER/ADMIN/CANCELLER roles are candidates; an open
EXECUTOR role alone (with a trusted proposer) is not treated as critical.
"""
from __future__ import annotations

from .base import Detector, FindingCandidate, TargetContext, role_hash

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD"

# role -> (impact-if-open-to-zero, is_critical_alone)
ROLES = {
    "DEFAULT_ADMIN_ROLE": (10, True),
    "TIMELOCK_ADMIN_ROLE": (9, True),
    "PROPOSER_ROLE": (9, True),
    "CANCELLER_ROLE": (7, True),
    "EXECUTOR_ROLE": (5, False),  # open executor alone is not critical
}


class TimelockRolesDetector(Detector):
    name = "timelock_roles"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        oc = ctx.onchain
        if not oc.available:
            return findings

        # Only meaningful if the contract looks like AccessControl/Timelock.
        src = ctx.all_source_text().lower()
        abi_names = {n.lower() for n in ctx.abi_function_names()}
        looks_accesscontrol = (
            "hasrole" in src
            or "accesscontrol" in src
            or "timelock" in src
            or "hasrole" in abi_names
            or "getmindelay" in abi_names
        )
        # Even without source we can probe hasRole on-chain; do a cheap probe.
        probe = oc.has_role(ctx.address, role_hash("DEFAULT_ADMIN_ROLE"), DEAD_ADDRESS)
        if not looks_accesscontrol and probe is None:
            return findings

        min_delay = oc.get_min_delay(ctx.address)
        role_evidence: dict = {"min_delay": min_delay, "checks": {}}

        for role_name, (impact, critical_alone) in ROLES.items():
            rh = role_hash(role_name)
            zero_has = oc.has_role(ctx.address, rh, ZERO_ADDRESS)
            dead_has = oc.has_role(ctx.address, rh, DEAD_ADDRESS)
            role_evidence["checks"][role_name] = {
                "role_hash": "0x" + rh.hex(),
                "zero_address_has_role": zero_has,
                "dead_address_has_role": dead_has,
            }

            # An open role granted to the zero/dead address is the red flag.
            open_to_anyone = bool(zero_has) or bool(dead_has)
            if not open_to_anyone:
                continue

            confidence = 7.0  # on-chain read confirmed the open role
            if not critical_alone:
                # e.g. EXECUTOR open: lower severity unless proposer also open.
                proposer_open = role_evidence["checks"].get("PROPOSER_ROLE", {})
                if proposer_open.get("zero_address_has_role") or proposer_open.get(
                    "dead_address_has_role"
                ):
                    severity = "high"
                else:
                    severity = "low"
                    impact = 4
                    confidence = 5.0
            else:
                severity = "critical" if impact >= 9 else "high"

            findings.append(
                FindingCandidate(
                    detector=self.name,
                    title=f"Open {role_name} (granted to zero/dead address)",
                    description=(
                        f"On-chain hasRole() shows {role_name} is held by the "
                        f"{'zero' if zero_has else 'dead'} address. If this role grants "
                        "privileged actions (propose/admin/cancel/upgrade), it may be "
                        "callable by anyone. Verify the role's powers and any timelock delay."
                    ),
                    impact_score=float(impact),
                    confidence_score=confidence,
                    severity_candidate=severity,
                    evidence={
                        "address": ctx.address,
                        "role": role_name,
                        **role_evidence["checks"][role_name],
                        "min_delay_seconds": min_delay,
                    },
                    next_tests=[
                        f"Confirm what {role_name} can call (grant/upgrade/execute selectors)",
                        "Check getMinDelay() and whether actions are timelocked",
                        "Verify on a fork that the open role actually authorizes a privileged call",
                    ],
                    affected_functions=[role_name],
                )
            )

        if not findings and min_delay is not None:
            # Informational: record the timelock delay even when no open role.
            findings.append(
                FindingCandidate(
                    detector=self.name,
                    title="Timelock present (no open role detected)",
                    description=(
                        f"Contract exposes getMinDelay() = {min_delay}s and no canonical "
                        "role was found open to the zero/dead address. Recorded as info."
                    ),
                    impact_score=2.0,
                    confidence_score=4.0,
                    severity_candidate="info",
                    evidence=role_evidence,
                    next_tests=["Enumerate actual role members via RoleGranted logs (eth_getLogs)"],
                )
            )

        return findings
