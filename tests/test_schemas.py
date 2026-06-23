"""Tests for request-schema validation."""
import pytest
from pydantic import ValidationError

from backend.schemas import SCAN_PROFILES, CreateScanRequest


def test_valid_profiles_accepted():
    for p in SCAN_PROFILES:
        req = CreateScanRequest(addresses_blob="0x", scan_profile=p)
        assert req.scan_profile == p


def test_unknown_profile_coerced_to_deep():
    # single-mode build: any client value is coerced to the one 'deep' profile
    req = CreateScanRequest(addresses_blob="0x", scan_profile="totally-made-up")
    assert req.scan_profile == "deep"


def test_deep_and_ultradeep_valid():
    assert SCAN_PROFILES == ["deep", "ultra-deep"]
    CreateScanRequest(scan_profile="deep")
    CreateScanRequest(scan_profile="ultra-deep")
