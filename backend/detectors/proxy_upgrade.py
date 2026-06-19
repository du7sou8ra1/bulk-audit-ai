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

        # Classify the controlling admin on-chain (Wasabi/Drift signal): EOA vs
        # multisig vs timelock. An EOA admin over an upgrade path is high-risk.
        admin_addr = proxy.admin_owner or proxy.owner or proxy.admin
        admin_class: dict = {}
        try:
            if ctx.onchain is not None and admin_addr:
                admin_class = ctx.onchain.classify_admin(admin_addr)
        except Exception:  # pragma: no cover - defensive
            admin_class = {}
        admin_is_eoa = admin_class.get("kind") == "eoa"

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
                eoa_risk = admin_is_eoa and is_code_upgrade
                findings.append(
                    FindingCandidate(
                        detector=self.name,
                        title=(
                            f"Upgrade function controlled by a single EOA admin: {fn.name}"
                            if eoa_risk
                            else f"Upgrade/ownership function guarded by access control: {fn.name}"
                        ),
                        description=(
                            (
                                f"`{fn.name}` is guarded, but the controlling admin "
                                f"({admin_addr}) is an externally-owned account (EOA) — not a "
                                "multisig or timelock. A single key compromise enables an instant "
                                "malicious upgrade and full drain (the Wasabi class)."
                            )
                            if eoa_risk
                            else (
                                f"`{fn.name}` is {fn.visibility} but carries an access-control "
                                f"modifier ({', '.join(fn.modifiers) or 'modifier present'}). "
                                "Governance/admin power, not necessarily a bug. The controlling "
                                f"admin classified on-chain as: {admin_class.get('kind', 'unknown')}."
                            )
                        ),
                        impact_score=float(base_impact),
                        confidence_score=6.0 if eoa_risk else 2.0,
                        severity_candidate="critical" if eoa_risk else "low",
                        evidence={
                            **evidence,
                            "admin_classification": admin_class,
                            # EOA admin is a real centralization risk -> don't -3 it.
                            "governance_controlled": not eoa_risk,
                            "documented_centralization": not eoa_risk,
                            "bug_class": "access_control",
                        },
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
