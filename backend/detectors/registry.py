"""Detector registry + per-profile selection."""
from __future__ import annotations

from .access_control import AccessControlDetector
from .arbitrary_call import ArbitraryCallDetector
from .base import Detector
from .bridge_accounting import BridgeAccountingDetector
from .delegatecall import DelegatecallDetector
from .governance_blast_radius import GovernanceBlastRadiusDetector
from .permit_misuse import PermitMisuseDetector
from .privacy_pool import PrivacyPoolDetector
from .proxy_upgrade import ProxyUpgradeDetector
from .timelock_roles import TimelockRolesDetector
from .token_logic import TokenLogicDetector
from .zk_verifier import ZkVerifierDetector

# All known detectors (fully-implemented + stubs).
ALL_DETECTORS: list[type[Detector]] = [
    ProxyUpgradeDetector,
    TimelockRolesDetector,
    ArbitraryCallDetector,
    PermitMisuseDetector,
    GovernanceBlastRadiusDetector,
    # stubs (return no findings in v0.1):
    DelegatecallDetector,
    AccessControlDetector,
    TokenLogicDetector,
    BridgeAccountingDetector,
    ZkVerifierDetector,
    PrivacyPoolDetector,
]

# Fully-implemented MVP detectors.
MVP_DETECTORS: list[type[Detector]] = [
    ProxyUpgradeDetector,
    TimelockRolesDetector,
    ArbitraryCallDetector,
    PermitMisuseDetector,
    GovernanceBlastRadiusDetector,
]

_PROFILE_MAP: dict[str, list[type[Detector]]] = {
    "quick": [ProxyUpgradeDetector, ArbitraryCallDetector],
    "standard": MVP_DETECTORS,
    "deep": ALL_DETECTORS,
    "governance-focused": [
        GovernanceBlastRadiusDetector,
        TimelockRolesDetector,
        ProxyUpgradeDetector,
    ],
    "zk-focused": MVP_DETECTORS + [ZkVerifierDetector],
    "privacy-pool-focused": MVP_DETECTORS + [PrivacyPoolDetector],
    "bridge-focused": MVP_DETECTORS + [BridgeAccountingDetector],
}


def get_detectors(profile: str) -> list[Detector]:
    classes = _PROFILE_MAP.get(profile, MVP_DETECTORS)
    # De-duplicate while preserving order.
    seen: set[type[Detector]] = set()
    instances: list[Detector] = []
    for cls in classes:
        if cls in seen:
            continue
        seen.add(cls)
        instances.append(cls())
    return instances
