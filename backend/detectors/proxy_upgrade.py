"""Detector: public/unprotected upgrade & ownership-transfer functions.

Flags upgrade-style functions and classifies them as *serious candidates* only
when they are externally reachable with no visible access control. A guarded
upgrade is normal governance power, not a bug — it is recorded as low/info.
"""
from __future__ import annotations

from .base import Detector, FindingCandidate, TargetContext, is_externally_callable

# name -> (base impact if unguarded, is it an upgrade of code)
UPGRADE_FUNCS = {
    "upgrade": (9, True),
    "upgradeTo": (9, True),
    "upgradeToAndCall": (9, True),
    "upgradeAndCall": (9, True),
    "setImplementation": (9, True),
    "changeImplementation": (9, True),
    "diamondCut": (9, True),
    "changeProxyAdmin": (8, True),
    "transferOwnership": (7, False),
    "renounceOwnership": (6, False),
}


class ProxyUpgradeDetector(Detector):
    name = "proxy_upgrade"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        proxy = ctx.proxy_info

        for fn in ctx.functions():
            if fn.name not in UPGRADE_FUNCS:
                continue
            if not is_externally_callable(fn):
                continue

            base_impact, is_code_upgrade = UPGRADE_FUNCS[fn.name]
            guarded = fn.has_access_control

            evidence = {
                "function": fn.name,
                "visibility": fn.visibility,
                "modifiers": fn.modifiers,
                "file": fn.file,
                "line": fn.line,
                "snippet": fn.snippet,
                "has_access_control": guarded,
                "proxy_admin": proxy.admin,
                "proxy_admin_owner": proxy.admin_owner,
                "owner": proxy.owner,
                "implementation": proxy.implementation,
            }
            next_tests = [
                f"eth_call {fn.name}(...) from a random EOA on a fork; expect revert if guarded",
                "Confirm proxy admin/owner is a Timelock or multisig (not an open EOA)",
            ]

            if guarded:
                # Governance power by design unless owner/admin is unexpected.
                findings.append(
                    FindingCandidate(
                        detector=self.name,
                        title=f"Upgrade/ownership function guarded by access control: {fn.name}",
                        description=(
                            f"`{fn.name}` is {fn.visibility} but carries an access-control "
                            f"modifier ({', '.join(fn.modifiers) or 'modifier present'}). "
                            "This is governance/admin power, not necessarily a bug. Verify "
                            "the controlling owner/admin is the expected timelock/multisig."
                        ),
                        impact_score=float(base_impact),
                        confidence_score=2.0,
                        severity_candidate="low",
                        evidence=evidence,
                        next_tests=next_tests,
                        affected_functions=[fn.name],
                    )
                )
            else:
                findings.append(
                    FindingCandidate(
                        detector=self.name,
                        title=f"Potentially unprotected upgrade function: {fn.name}",
                        description=(
                            f"`{fn.name}` is {fn.visibility} and no access-control modifier "
                            "was detected near its declaration. If reachable on a funded "
                            "proxy/implementation, this could allow arbitrary code upgrade "
                            "or ownership takeover. Requires PoC/fork confirmation."
                        ),
                        impact_score=float(base_impact),
                        confidence_score=6.0 if is_code_upgrade else 5.0,
                        severity_candidate="critical" if is_code_upgrade else "high",
                        evidence=evidence,
                        next_tests=next_tests,
                        affected_functions=[fn.name],
                    )
                )

        return findings
