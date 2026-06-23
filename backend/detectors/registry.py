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
from .solvency_check import SolvencyCheckDetector
from .flashloan_governance import FlashloanGovernanceDetector
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
    SolvencyCheckDetector,        # Euler donateToReserves (missing liquidity check) (v0.5)
    FlashloanGovernanceDetector,  # Beanstalk (spot-power vote + same-tx exec) (v0.5)
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

# Single-mode build (user request): ONE profile, "deep", runs EVERY detector.
# "ultra-deep" is intentionally NOT defined -- that name is reserved for the next
# wave of enhancements. Until then, "deep" == the full set.
FULL_DETECTORS: list[type[Detector]] = [
    *MVP_DETECTORS,
    *ATTACK_CLASS_DETECTORS,
    *EXPLOIT_2026_DETECTORS,
    DelegatecallDetector,
    PrivacyPoolDetector,
]

# New detectors that run ONLY under ultra-deep (deep stays frozen). Filled as the
# 2020-2026 enhancement wave lands.
ULTRA_EXTRA_DETECTORS: list[type[Detector]] = []

_PROFILE_MAP: dict[str, list[type[Detector]]] = {
    # "deep" = the current engine, FROZEN. "ultra-deep" = deep + ctx.profile-gated
    # enhanced heuristics in existing detectors + ULTRA_EXTRA_DETECTORS new classes.
    "deep": FULL_DETECTORS,
    "ultra-deep": FULL_DETECTORS + ULTRA_EXTRA_DETECTORS,
}


# Public, single source of truth for valid profile names (the API schema imports
# this so it can never drift from the registry again).
PROFILE_NAMES: list[str] = list(_PROFILE_MAP.keys())


def get_detectors(profile: str) -> list[Detector]:
    classes = _PROFILE_MAP.get(profile, FULL_DETECTORS)
    seen: set[type[Detector]] = set()
    instances: list[Detector] = []
    for cls in classes:
        if cls in seen:
            continue
        seen.add(cls)
        instances.append(cls())
    return instances
