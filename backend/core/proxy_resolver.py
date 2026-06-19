"""Proxy / implementation / admin resolution.

Primary strategy is EIP-1967 storage-slot reads (deterministic, ABI-free).
Secondary strategy is a set of well-known ABI getters, each wrapped so it can
never abort a scan. EIP-1167 minimal proxies are detected from bytecode.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from eth_utils import keccak, to_checksum_address

from .onchain import OnchainClient


def _slot_from_label(label: str) -> int:
    """EIP-1967 slot = keccak256(label) - 1."""
    return int.from_bytes(keccak(text=label), "big") - 1


# Canonical EIP-1967 slots (computed, with their well-known hex values).
IMPL_SLOT = _slot_from_label("eip1967.proxy.implementation")
ADMIN_SLOT = _slot_from_label("eip1967.proxy.admin")
BEACON_SLOT = _slot_from_label("eip1967.proxy.beacon")

# Legacy OpenZeppelin / zeppelinos slot.
LEGACY_IMPL_SLOT = int.from_bytes(keccak(text="org.zeppelinos.proxy.implementation"), "big")


@dataclass
class ProxyInfo:
    is_proxy: bool = False
    proxy_type: str | None = None
    implementation: str | None = None
    admin: str | None = None
    admin_owner: str | None = None
    beacon: str | None = None
    owner: str | None = None
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "is_proxy": self.is_proxy,
            "proxy_type": self.proxy_type,
            "implementation": self.implementation,
            "admin": self.admin,
            "admin_owner": self.admin_owner,
            "beacon": self.beacon,
            "owner": self.owner,
            "evidence": self.evidence,
        }


def _detect_minimal_proxy(code: str | None) -> str | None:
    """Detect EIP-1167 minimal proxy and return the target address, if any."""
    if not code:
        return None
    c = code.lower().replace("0x", "")
    # Standard EIP-1167 runtime: 363d3d373d3d3d363d73<20-byte addr>5af43d82803e903d91602b57fd5bf3
    marker = "363d3d373d3d3d363d73"
    if marker in c:
        idx = c.index(marker) + len(marker)
        addr_hex = c[idx : idx + 40]
        if len(addr_hex) == 40 and int(addr_hex, 16) != 0:
            try:
                return to_checksum_address("0x" + addr_hex)
            except Exception:
                return "0x" + addr_hex
    return None


def resolve_proxy(
    onchain: OnchainClient,
    address: str,
    abi: list | dict | None = None,
    explorer_implementation: str | None = None,
) -> ProxyInfo:
    info = ProxyInfo()
    ev: dict = {"slot_reads": {}, "abi_calls": {}, "notes": []}

    if not onchain.available:
        ev["notes"].append("RPC unavailable; proxy resolution limited to explorer data")
        if explorer_implementation:
            info.is_proxy = True
            info.proxy_type = "explorer-reported"
            info.implementation = explorer_implementation
        info.evidence = ev
        return info

    # --- 1. EIP-1967 storage slots ------------------------------------- #
    impl = onchain.storage_to_address(address, IMPL_SLOT)
    admin = onchain.storage_to_address(address, ADMIN_SLOT)
    beacon = onchain.storage_to_address(address, BEACON_SLOT)
    ev["slot_reads"] = {
        "implementation_slot": hex(IMPL_SLOT),
        "implementation_value": impl,
        "admin_slot": hex(ADMIN_SLOT),
        "admin_value": admin,
        "beacon_slot": hex(BEACON_SLOT),
        "beacon_value": beacon,
    }

    if impl:
        info.is_proxy = True
        info.implementation = impl
        info.admin = admin
        info.proxy_type = "eip1967-transparent" if admin else "eip1967-uups"
    elif beacon:
        info.is_proxy = True
        info.beacon = beacon
        info.proxy_type = "eip1967-beacon"
        # Beacon exposes implementation()
        beacon_impl = onchain.try_address_getter(beacon, "implementation()")
        if beacon_impl:
            info.implementation = beacon_impl
        ev["abi_calls"]["beacon.implementation()"] = beacon_impl

    # --- 2. Legacy slot ------------------------------------------------- #
    if not info.implementation:
        legacy = onchain.storage_to_address(address, LEGACY_IMPL_SLOT)
        ev["slot_reads"]["legacy_impl_value"] = legacy
        if legacy:
            info.is_proxy = True
            info.implementation = legacy
            info.proxy_type = info.proxy_type or "legacy-zos"

    # --- 3. EIP-1167 minimal proxy ------------------------------------- #
    if not info.implementation:
        code = onchain.get_code(address)
        minimal = _detect_minimal_proxy(code)
        if minimal:
            info.is_proxy = True
            info.implementation = minimal
            info.proxy_type = "eip1167-minimal"
            ev["notes"].append("EIP-1167 minimal proxy detected from bytecode")

    # --- 4. ABI getter fallbacks --------------------------------------- #
    if not info.implementation:
        for sig in ("implementation()", "getImplementation()", "masterCopy()"):
            val = onchain.try_address_getter(address, sig)
            ev["abi_calls"][sig] = val
            if val:
                info.is_proxy = True
                info.implementation = val
                info.proxy_type = info.proxy_type or "abi-getter"
                break

    if not info.admin:
        for sig in ("admin()", "proxyAdmin()", "getProxyAdmin()"):
            val = onchain.try_address_getter(address, sig)
            ev["abi_calls"][sig] = val
            if val:
                info.admin = val
                break

    # --- 5. Ownership ---------------------------------------------------- #
    info.owner = onchain.try_address_getter(address, "owner()")
    ev["abi_calls"]["owner()"] = info.owner

    # ProxyAdmin.owner() — who controls upgrades on a transparent proxy.
    if info.admin:
        info.admin_owner = onchain.try_address_getter(info.admin, "owner()")
        ev["abi_calls"]["admin.owner()"] = info.admin_owner

    # explorer cross-check
    if explorer_implementation:
        ev["explorer_implementation"] = explorer_implementation
        if not info.implementation:
            info.is_proxy = True
            info.implementation = explorer_implementation
            info.proxy_type = info.proxy_type or "explorer-reported"

    info.evidence = ev
    return info
