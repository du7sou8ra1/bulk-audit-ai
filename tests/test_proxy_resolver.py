"""Tests for the EIP-1967 slot math and minimal-proxy detection."""
from backend.core.proxy_resolver import (
    ADMIN_SLOT,
    BEACON_SLOT,
    IMPL_SLOT,
    _detect_minimal_proxy,
)

# Canonical, well-known EIP-1967 slot values.
KNOWN_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
KNOWN_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
KNOWN_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"


def test_eip1967_slot_constants():
    assert hex(IMPL_SLOT) == KNOWN_IMPL
    assert hex(ADMIN_SLOT) == KNOWN_ADMIN
    assert hex(BEACON_SLOT) == KNOWN_BEACON


def test_detect_minimal_proxy_match():
    impl = "1234567890123456789012345678901234567890"
    code = "0x363d3d373d3d3d363d73" + impl + "5af43d82803e903d91602b57fd5bf3"
    found = _detect_minimal_proxy(code)
    assert found is not None
    assert found.lower().endswith(impl)


def test_detect_minimal_proxy_none():
    assert _detect_minimal_proxy("0x6080604052") is None
    assert _detect_minimal_proxy(None) is None
    assert _detect_minimal_proxy("0x") is None
