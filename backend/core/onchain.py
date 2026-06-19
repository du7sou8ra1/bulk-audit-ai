"""Read-only on-chain access.

HARD SAFETY RULE: this module exposes ONLY read methods:
    eth_call, eth_getStorageAt, eth_getCode, eth_getBalance, eth_getLogs.
There is deliberately NO support for eth_sendTransaction / eth_sendRawTransaction,
private keys, signing, or any state-changing call. Do not add them.

All helpers are defensive: a failing RPC call returns ``None`` (or logs an
evidence note) instead of raising, so one bad read never aborts a scan.
"""
from __future__ import annotations

import logging

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import function_signature_to_4byte_selector, to_checksum_address
from web3 import Web3

from ..config import get_settings

logger = logging.getLogger("bulkauditai.onchain")

# Methods that are explicitly forbidden. Used as a tripwire in tests.
FORBIDDEN_RPC_METHODS = frozenset(
    {
        "eth_sendTransaction",
        "eth_sendRawTransaction",
        "eth_sign",
        "eth_signTransaction",
        "personal_sendTransaction",
        "personal_sign",
    }
)


class OnchainClient:
    """Thin, read-only wrapper around web3.py."""

    def __init__(self, rpc_url: str | None = None, chain: str | None = None):
        s = get_settings()
        self.chain = chain
        self.rpc_url = rpc_url or (s.rpc_url_for(chain) if chain else s.rpc_url)
        self._w3: Web3 | None = None

    # ------------------------------------------------------------------ #
    @property
    def w3(self) -> Web3 | None:
        if self._w3 is None and self.rpc_url:
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 30}))
        return self._w3

    @property
    def available(self) -> bool:
        try:
            return bool(self.w3) and self.w3.is_connected()
        except Exception:
            return False

    @staticmethod
    def checksum(address: str) -> str:
        return to_checksum_address(address)

    # ------------------------------------------------------------------ #
    # Primitive reads
    # ------------------------------------------------------------------ #
    def get_code(self, address: str) -> str | None:
        if not self.w3:
            return None
        try:
            code = self.w3.eth.get_code(self.checksum(address))
            return code.hex()
        except Exception as exc:
            logger.debug("get_code(%s) failed: %s", address, exc)
            return None

    def has_code(self, address: str) -> bool | None:
        code = self.get_code(address)
        if code is None:
            return None
        return code not in ("0x", "0x0", "")

    def get_balance_eth(self, address: str) -> float | None:
        if not self.w3:
            return None
        try:
            wei = self.w3.eth.get_balance(self.checksum(address))
            return float(self.w3.from_wei(wei, "ether"))
        except Exception as exc:
            logger.debug("get_balance(%s) failed: %s", address, exc)
            return None

    def get_storage_at(self, address: str, slot: int | str) -> str | None:
        """Return the 32-byte storage word at ``slot`` as a 0x-hex string."""
        if not self.w3:
            return None
        try:
            raw = self.w3.eth.get_storage_at(self.checksum(address), slot)
            return raw.hex()
        except Exception as exc:
            logger.debug("get_storage_at(%s, %s) failed: %s", address, slot, exc)
            return None

    def storage_to_address(self, address: str, slot: int | str) -> str | None:
        """Read a storage slot and interpret its low 20 bytes as an address."""
        word = self.get_storage_at(address, slot)
        if not word:
            return None
        h = word[2:] if word.startswith("0x") else word
        h = h.rjust(64, "0")
        addr_hex = "0x" + h[-40:]
        if int(addr_hex, 16) == 0:
            return None
        try:
            return self.checksum(addr_hex)
        except Exception:
            return addr_hex

    def eth_call_raw(self, to: str, data: str) -> str | None:
        if not self.w3:
            return None
        try:
            result = self.w3.eth.call({"to": self.checksum(to), "data": data})
            return result.hex()
        except Exception as exc:
            logger.debug("eth_call(%s, %s) failed: %s", to, data[:10], exc)
            return None

    # ------------------------------------------------------------------ #
    # Typed call helper (no ABI needed)
    # ------------------------------------------------------------------ #
    def call_typed(
        self,
        address: str,
        signature: str,
        arg_types: list[str] | None = None,
        args: list | None = None,
        return_types: list[str] | None = None,
    ):
        """Encode + perform an ``eth_call`` and ABI-decode the result.

        ``signature`` is e.g. ``"hasRole(bytes32,address)"``.
        Returns the decoded tuple, a single value if one return type, or None.
        """
        selector = function_signature_to_4byte_selector(signature)
        encoded_args = b""
        if arg_types and args is not None:
            try:
                encoded_args = abi_encode(arg_types, args)
            except Exception as exc:
                logger.debug("encode failed for %s: %s", signature, exc)
                return None
        data = "0x" + (selector + encoded_args).hex()
        raw = self.eth_call_raw(address, data)
        if raw is None:
            return None
        if not return_types:
            return raw
        try:
            raw_bytes = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
            if not raw_bytes:
                return None
            decoded = abi_decode(return_types, raw_bytes)
            return decoded[0] if len(return_types) == 1 else decoded
        except Exception as exc:
            logger.debug("decode failed for %s: %s", signature, exc)
            return None

    # Convenience wrappers used by the proxy resolver / detectors -------- #
    def try_address_getter(self, address: str, signature: str) -> str | None:
        val = self.call_typed(address, signature, return_types=["address"])
        if val and int(val, 16) != 0:
            try:
                return self.checksum(val)
            except Exception:
                return val
        return None

    def has_role(self, contract: str, role: bytes, account: str) -> bool | None:
        return self.call_typed(
            contract,
            "hasRole(bytes32,address)",
            ["bytes32", "address"],
            [role, self.checksum(account)],
            ["bool"],
        )

    def get_min_delay(self, contract: str) -> int | None:
        return self.call_typed(contract, "getMinDelay()", return_types=["uint256"])

    # ------------------------------------------------------------------ #
    # Admin classifier (Wasabi / Drift / Truebit signal): is the owner/admin
    # an unprotected EOA, a multisig, or a timelock?  Read-only.
    # ------------------------------------------------------------------ #
    def classify_admin(self, address: str | None) -> dict:
        """Classify an owner/admin address as eoa | gnosis_safe | timelock | contract.

        An EOA owner of an upgrade/withdraw path is the high-risk shape (a single
        compromised key drains the protocol). A Safe/timelock is normal governance.
        """
        result = {"address": address, "kind": "unknown", "is_eoa": None,
                  "threshold": None, "min_delay": None}
        if not address or not self.w3:
            return result
        code = self.get_code(address)
        if code is None:
            return result
        if code in ("0x", "0x0", ""):
            result["kind"] = "eoa"
            result["is_eoa"] = True
            return result
        result["is_eoa"] = False
        # Gnosis Safe? getThreshold()/getOwners()
        threshold = self.call_typed(address, "getThreshold()", return_types=["uint256"])
        if isinstance(threshold, int) and threshold >= 1:
            result["kind"] = "gnosis_safe"
            result["threshold"] = threshold
            return result
        # OZ TimelockController? getMinDelay()
        delay = self.get_min_delay(address)
        if isinstance(delay, int):
            result["kind"] = "timelock"
            result["min_delay"] = delay
            return result
        result["kind"] = "contract"
        return result
