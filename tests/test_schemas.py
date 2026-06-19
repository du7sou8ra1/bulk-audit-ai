"""Tests for request-schema validation."""
import pytest
from pydantic import ValidationError

from backend.schemas import SCAN_PROFILES, CreateScanRequest


def test_valid_profiles_accepted():
    for p in SCAN_PROFILES:
        req = CreateScanRequest(addresses_blob="0x", scan_profile=p)
        assert req.scan_profile == p


def test_unknown_profile_rejected():
    with pytest.raises(ValidationError):
        CreateScanRequest(addresses_blob="0x", scan_profile="totally-made-up")


def test_bridge_focused_is_valid():
    assert "bridge-focused" in SCAN_PROFILES
    CreateScanRequest(scan_profile="bridge-focused")
