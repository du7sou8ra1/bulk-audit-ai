"""Single-mode build: 'deep' is the ONLY scan profile and it runs every detector.
The API validator must stay in lock-step with the registry, and the registry must
never silently degrade an unknown profile to a smaller set.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_profiles.py -q
"""
import pytest

from backend.detectors.registry import (
    FULL_DETECTORS,
    PROFILE_NAMES,
    ULTRA_DEEP_V2_EXTRA_DETECTORS,
    ULTRA_EXTRA_DETECTORS,
    get_detectors,
)
from backend.detectors.bytecode_periphery import BytecodePeripheryDetector
from backend.schemas import SCAN_PROFILES, CreateScanRequest


def test_schema_profiles_match_registry():
    assert set(SCAN_PROFILES) == set(PROFILE_NAMES)


def test_deep_ultradeep_and_v2_profiles():
    assert PROFILE_NAMES == ["deep", "ultra-deep", "ultra-deep-v2"]


def test_deep_runs_every_detector():
    assert len(get_detectors("deep")) == len(set(FULL_DETECTORS))


def test_create_scan_accepts_deep():
    req = CreateScanRequest(scan_profile="deep", addresses_blob="0x" + "11" * 20)
    assert req.scan_profile == "deep"
    assert get_detectors("deep")


def test_ultra_deep_v2_superset():
    ultra = {type(d) for d in get_detectors("ultra-deep")}
    v2 = {type(d) for d in get_detectors("ultra-deep-v2")}
    assert ultra <= v2
    assert {cls for cls in ULTRA_DEEP_V2_EXTRA_DETECTORS} <= v2
    assert BytecodePeripheryDetector in v2
    assert len(get_detectors("ultra-deep")) == len(set(FULL_DETECTORS + ULTRA_EXTRA_DETECTORS))


def test_unknown_profile_coerced_and_never_degrades():
    # API coerces any value to 'deep' (single mode); the registry never degrades either
    req = CreateScanRequest(scan_profile="totally-made-up", addresses_blob="0x" + "11" * 20)
    assert req.scan_profile == "deep"
    assert len(get_detectors("totally-made-up")) == len(get_detectors("deep"))
