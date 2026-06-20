"""Detector registry + per-profile selection."""
from __future__ import annotations

from .access_control import AccessControlDetector
from .arbitrary_call import ArbitraryCallDetector
from .exploit_2026 import (
    AsymmetricSafeMathDetector,
    CrossChainTrustDetector,
    DepositCallbackCEIDetector,
    EncodePackedCollisionDetector,
    FeeOnTransferSwapBoundsDetector,
    HookCallbackAuthDetector,
    HookPairBurnSyncDetector,
    MemoryStructPersistenceDetector,
    ReceiverHookCreditDetector,
    SelfCallAuthBypassDetector,
    SignerAllowlistDetector,
    UnprotectedInitializerDetector,
)
from .arithmetic_logic import ArithmeticLogicDetector
from .base import Detector
from .bridge_accounting import BridgeAccountingDetector
from .delegatecall import DelegatecallDetector
from .governance_blast_radius import GovernanceBlastRadiusDetector
from .oracle_manipulation import OracleManipulationDetector
from .permit_misuse import PermitMisuseDetector
from .privacy_pool import PrivacyPoolDetector
from .proxy_upgrade import ProxyUpgradeDetector
from .reentrancy import ReentrancyDetector
from .signature_replay import SignatureReplayDetector
from .time_logic import TimeLogicDetector
from .timelock_roles import TimelockRolesDetector
from .token_logic import TokenLogicDetector
from .zk_verifier import ZkVerifierDetector

# Fully-implemented MVP detectors (access-control / proxy / governance core).
MVP_DETECTORS: list[type[Detector]] = [
    ProxyUpgradeDetector,
    TimelockRolesDetector,
    ArbitraryCallDetector,
    PermitMisuseDetector,
    GovernanceBlastRadiusDetector,
]

# v0.4 attack-class detectors mapped to the 2026 incident taxonomy.
ATTACK_CLASS_DETECTORS: list[type[Detector]] = [
    AccessControlDetector,        # Truebit / Wasabi
    OracleManipulationDetector,   # YieldBlox / Venus / LML / BlindBox / MakinaFi
    ArithmeticLogicDetector,      # MakinaFi / Solv / Truebit
    ReentrancyDetector,           # Venus
    SignatureReplayDetector,      # GnosisPay / Drift
    TokenLogicDetector,           # SOF / LAXO
    TimeLogicDetector,            # DxSale
    BridgeAccountingDetector,     # KelpDAO / Gravity (on-chain part)
    ZkVerifierDetector,           # Aztec settlement binding + FOOMCASH/Veil Groth16
]

# All known detectors (implemented + remaining stubs).
ALL_DETECTORS: list[type[Detector]] = [
    *MVP_DETECTORS,
    *ATTACK_CLASS_DETECTORS,
    # remaining stubs (return no findings yet):
    DelegatecallDetector,
    PrivacyPoolDetector,
]

# v0.9 "ultra-deep" detectors: one family per 2026 on-chain incident class
# (Cork/Ekubo hooks, CrossCurve/Gyroscope cross-chain, Aurellion/Renegade
# initializer, ShapeShift self-call, Butter encodePacked, SOFI/BUBU2 transfer
# hooks, Solv ERC-3525 CEI, Synap fee-on-transfer, Truebit SafeMath, MoltEVM
# memory-not-storage, TrustedVolumes signer allowlist).
EXPLOIT_2026_DETECTORS: list[type[Detector]] = [
    HookCallbackAuthDetector,
    CrossChainTrustDetector,
    UnprotectedInitializerDetector,
    SelfCallAuthBypassDetector,
    EncodePackedCollisionDetector,
    HookPairBurnSyncDetector,
    DepositCallbackCEIDetector,
    ReceiverHookCreditDetector,
    FeeOnTransferSwapBoundsDetector,
    AsymmetricSafeMathDetector,
    MemoryStructPersistenceDetector,
    SignerAllowlistDetector,
]

_PROFILE_MAP: dict[str, list[type[Detector]]] = {
    "quick": [ProxyUpgradeDetector, ArbitraryCallDetector, AccessControlDetector],
    "standard": MVP_DETECTORS + [AccessControlDetector, OracleManipulationDetector],
    "deep": ALL_DETECTORS,
    # The most exhaustive profile: deep + a detector family per 2026 incident class.
    "ultra-deep": ALL_DETECTORS + EXPLOIT_2026_DETECTORS,
    # Covers the maximum of the 2026 code-findable incident list.
    "defi-deep": MVP_DETECTORS + ATTACK_CLASS_DETECTORS,
    "governance-focused": [
        GovernanceBlastRadiusDetector,
        TimelockRolesDetector,
        ProxyUpgradeDetector,
        AccessControlDetector,
    ],
    "oracle-focused": [OracleManipulationDetector, TokenLogicDetector, ReentrancyDetector],
    "zk-focused": MVP_DETECTORS + [
        ZkVerifierDetector, ReentrancyDetector, BridgeAccountingDetector,
        SignatureReplayDetector,
    ],
    "privacy-pool-focused": MVP_DETECTORS + [PrivacyPoolDetector],
    "bridge-focused": MVP_DETECTORS + [BridgeAccountingDetector, SignatureReplayDetector],
}


# Public, single source of truth for valid profile names (the API schema imports
# this so it can never drift from the registry again).
PROFILE_NAMES: list[str] = list(_PROFILE_MAP.keys())


def get_detectors(profile: str) -> list[Detector]:
    classes = _PROFILE_MAP.get(profile, MVP_DETECTORS)
    seen: set[type[Detector]] = set()
    instances: list[Detector] = []
    for cls in classes:
        if cls in seen:
            continue
        seen.add(cls)
        instances.append(cls())
    return instances
