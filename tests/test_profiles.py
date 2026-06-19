"""The API scan_profile validator must accept every profile the registry defines
(it went stale once and rejected 'defi-deep' with a 422).
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_profiles.py -q
"""
import pytest

from backend.detectors.registry import PROFILE_NAMES, get_detectors
from backend.schemas import SCAN_PROFILES, CreateScanRequest


def test_schema_profiles_match_registry():
    assert set(SCAN_PROFILES) == set(PROFILE_NAMES)
    assert "defi-deep" in SCAN_PROFILES
    assert "oracle-focused" in SCAN_PROFILES


def test_create_scan_accepts_registry_profiles():
    for p in PROFILE_NAMES:
        req = CreateScanRequest(scan_profile=p, addresses_blob="0x" + "11" * 20)
        assert req.scan_profile == p
        assert get_detectors(p)  # the registry actually resolves it to detectors


def test_create_scan_rejects_unknown_profile():
    with pytest.raises(Exception):
        CreateScanRequest(scan_profile="totally-made-up")
