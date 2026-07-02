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
import re

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import function_signature_to_4byte_selector, to_checksum_address
from web3 import Web3

from ..config import get_settings

logger = logging.getLogger("bulkauditai.onchain")
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

_FLOW_NAME_RE = re.compile(
    r"swap|bridge|relay|route|execute|multicall|forward|deposit|withdraw|redeem|claim|settle",
    re.I,
)
_FLOW_SOURCE_RE = re.compile(
    r"(safeTransferFrom|transferFrom)\s*\([^;{]{0,160}(msg\.sender|from|payer|owner|src|source)"
    r"|(\.call\s*(?:\{|\.value|\())|safeTransfer\s*\(|\.transfer\s*\(",
    re.I,
)
_DEPENDENT_HINT_RE = re.compile(
    r"implementation|logic|facet|module|library|delegate|diamond|strategy|adapter",
    re.I,
)


def _is_zero_address(value) -> bool:
    try:
        return bool(value) and int(str(value), 16) == 0
    except Exception:
        return False


def _positive_int(value) -> bool:
    return isinstance(value, int) and value > 0


def _abi_value_flow_hint(abi) -> bool:
    if isinstance(abi, dict):
        abi = abi.get("abi")
    if not isinstance(abi, list):
        return False
    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        if item.get("stateMutability") == "payable":
            return True
        if _FLOW_NAME_RE.search(str(item.get("name") or "")):
            return True
    return False

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
    # Chain-attribution guard (Base-scan-hits-mainnet-RPC misconfig).
    # ------------------------------------------------------------------ #
    @property
    def expected_chain_id(self) -> int:
        """The numeric chainid the scan intends to target (from the chain name)."""
        return get_settings().etherscan_chain_id(self.chain)

    def live_chain_id(self) -> int | None:
        """The chainid the configured RPC node actually reports (None if unknown)."""
        if not self.w3:
            return None
        try:
            return int(self.w3.eth.chain_id)
        except Exception as exc:
            logger.debug("chain_id read failed: %s", exc)
            return None

    def chain_mismatch(self) -> bool | None:
        """True if the RPC node's chainid != the chain being scanned.

        ``rpc_url_for`` falls back to the default RPC when ``RPC_URL_<CHAIN>`` is
        unset, so scanning e.g. Base with only a mainnet RPC configured makes every
        read (get_code / balances / eth_call) resolve against MAINNET. Findings
        derived from those reads are then attributed to the wrong chain. Returns
        None when unknown (no RPC / read failed) — unknown must never suppress.
        """
        live = self.live_chain_id()
        if live is None:
            return None
        return live != self.expected_chain_id

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

    def eth_call_raw_from(
        self,
        to: str,
        data: str,
        from_addr: str,
        value: int = 0,
        block_identifier: str = "latest",
    ) -> dict:
        """Read-only eth_call with explicit caller/value context.

        This never sends a transaction. It is used for fork/RPC auth checks where
        the same calldata should be tested from an unprivileged address.
        """
        if not self.w3:
            return {"ok": None, "error": "rpc unavailable"}
        try:
            tx = {
                "to": self.checksum(to),
                "from": self.checksum(from_addr),
                "data": data,
                "value": int(value or 0),
            }
            result = self.w3.eth.call(tx, block_identifier=block_identifier)
            return {"ok": True, "return": result.hex()}
        except Exception as exc:
            logger.debug("eth_call_from(%s, %s, %s) failed: %s", from_addr, to, data[:10], exc)
            return {"ok": False, "error": str(exc)[:500]}

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

    # ------------------------------------------------------------------ #
    # Generalized value-context probe.
    # ------------------------------------------------------------------ #
    def probe_value_context(
        self,
        address: str,
        *,
        abi=None,
        source_text: str = "",
        referenced_by: list[dict] | list[str] | None = None,
        contract_name: str = "",
    ) -> dict:
        """Return conservative value-context evidence for scoring/refutation.

        ``state`` is tri-state: ``has_value``, ``no_value``, or ``unknown``.
        Unknown, including RPC/read failure, must never cap severity.
        """
        evidence = {
            "state": "unknown",
            "signal": "unknown",
            "native_balance_eth": None,
            "declared_assets": [],
            "self_asset_balances": [],
            "totals": {},
            "value_flow_hint": False,
            "dependent_hint": False,
            "referenced_by_count": None if referenced_by is None else len(referenced_by),
            "reference_state": "unknown" if referenced_by is None else ("present" if referenced_by else "none"),
            "notes": [],
        }
        if not self.available:
            evidence["notes"].append("rpc unavailable; value context is unknown")
            return evidence

        read_attempted = False
        read_failed = False

        try:
            native = self.get_balance_eth(address)
        except Exception:
            native = None
        read_attempted = True
        if native is None:
            read_failed = True
        else:
            evidence["native_balance_eth"] = native

        for sig in ("totalAssets()", "totalSupply()"):
            read_attempted = True
            try:
                val = self.call_typed(address, sig, return_types=["uint256"])
            except Exception:
                val = None
            if val is None:
                read_failed = True
            else:
                evidence["totals"][sig[:-2]] = val

        seen_assets: set[str] = set()
        for sig in ("asset()", "underlying()", "token()"):
            read_attempted = True
            try:
                raw = self.call_typed(address, sig, return_types=["address"])
            except Exception:
                raw = None
            if raw is None:
                read_failed = True
                continue
            if _is_zero_address(raw):
                evidence["declared_assets"].append({"getter": sig, "address": ZERO_ADDRESS, "zero": True})
                continue
            try:
                asset = self.checksum(raw)
            except Exception:
                asset = str(raw)
            if asset.lower() in seen_assets:
                continue
            seen_assets.add(asset.lower())
            evidence["declared_assets"].append({"getter": sig, "address": asset, "zero": False})
            read_attempted = True
            try:
                bal = self.call_typed(
                    asset,
                    "balanceOf(address)",
                    ["address"],
                    [self.checksum(address)],
                    ["uint256"],
                )
            except Exception:
                bal = None
            if bal is None:
                read_failed = True
            else:
                evidence["self_asset_balances"].append({"asset": asset, "balance": bal})

        source = source_text or ""
        flow_hint = _abi_value_flow_hint(abi) or bool(_FLOW_SOURCE_RE.search(source))
        dependent_hint = bool(_DEPENDENT_HINT_RE.search(f"{contract_name}\n{source[:8000]}"))
        evidence["value_flow_hint"] = flow_hint
        evidence["dependent_hint"] = dependent_hint

        has_value = (
            (isinstance(evidence["native_balance_eth"], (int, float)) and evidence["native_balance_eth"] > 0)
            or any(_positive_int(v) for v in evidence["totals"].values())
            or any(_positive_int(row.get("balance")) for row in evidence["self_asset_balances"])
        )
        if has_value:
            evidence["state"] = "has_value"
            evidence["signal"] = "self_holds_value"
            return evidence

        if not read_attempted or (read_failed and evidence["native_balance_eth"] is None and not evidence["totals"]):
            evidence["state"] = "unknown"
            evidence["signal"] = "unknown"
            evidence["notes"].append("value reads were inconclusive")
            return evidence

        evidence["state"] = "no_value"
        if flow_hint:
            evidence["signal"] = "value_flows_through"
        elif referenced_by:
            evidence["signal"] = "value_in_dependents"
        elif dependent_hint and referenced_by is None:
            evidence["signal"] = "value_in_dependents"
            evidence["notes"].append("dependency hint present but no reference index was provided")
        elif referenced_by == []:
            evidence["signal"] = "inert_unreferenced"
            evidence["notes"].append(
                "no declared/self-held value, no flow hint, and caller supplied an empty dependent-reference set"
            )
        else:
            evidence["signal"] = "unknown"
            evidence["notes"].append("no dependency index was provided; not treating zero balance as inert")
        return evidence

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
