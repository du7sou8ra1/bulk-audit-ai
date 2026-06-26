"""Bytecode intelligence for unverified or source-mismatched contracts.

This is intentionally dependency-light: it does not try to be a full EVM
decompiler. It builds the durable facts a decompiler lane needs first: runtime
hashes, metadata stripping, opcode counts, PUSH4 selector clusters, proxy
fingerprints, storage-slot constants, and high-signal bytecode risk clusters.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from eth_utils import keccak

from ..runners.base import RunnerResult


TOOL_NAME = "bytecode-intel"

_OPCODES = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    0x20: "SHA3",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5F: "PUSH0",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

for _i in range(1, 33):
    _OPCODES[0x5F + _i] = f"PUSH{_i}"
for _i in range(1, 17):
    _OPCODES[0x7F + _i] = f"DUP{_i}"
    _OPCODES[0x8F + _i] = f"SWAP{_i}"
for _i in range(5):
    _OPCODES[0xA0 + _i] = f"LOG{_i}"


_SELECTOR_SIGNATURES = (
    "admin()",
    "implementation()",
    "upgradeTo(address)",
    "upgradeToAndCall(address,bytes)",
    "changeAdmin(address)",
    "proxiableUUID()",
    "initialize()",
    "initialize(address)",
    "initialize(address,address)",
    "reinitialize(uint8)",
    "execute(address,uint256,bytes)",
    "execute(bytes)",
    "execute(bytes[])",
    "executeBatch(address[],uint256[],bytes[])",
    "multicall(bytes[])",
    "aggregate((address,bytes)[])",
    "call(address,uint256,bytes)",
    "delegatecall(address,bytes)",
    "transferFrom(address,address,uint256)",
    "safeTransferFrom(address,address,uint256)",
    "safeTransferFrom(address,address,uint256,bytes)",
    "approve(address,uint256)",
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "claim()",
    "claim(address)",
    "claimReward(address)",
    "settle()",
    "settle(address)",
    "checkpoint()",
    "lzReceive(uint16,bytes,uint64,bytes)",
    "ccipReceive((bytes32,uint64,bytes,bytes,(address,uint256)[]))",
    "receiveMessage(bytes)",
    "processMessage(bytes)",
)


def _selector(signature: str) -> str:
    return keccak(text=signature)[:4].hex()


KNOWN_SELECTORS: dict[str, list[str]] = {}
for _sig in _SELECTOR_SIGNATURES:
    KNOWN_SELECTORS.setdefault(_selector(_sig), []).append(_sig)


_SELECTOR_CLUSTERS = {
    "upgrade_admin": (
        "upgradeTo(",
        "upgradeToAndCall(",
        "changeAdmin(",
        "admin()",
        "implementation()",
        "proxiableUUID()",
        "initialize(",
        "reinitialize(",
    ),
    "arbitrary_execution": (
        "execute(",
        "executeBatch(",
        "multicall(",
        "aggregate(",
        "call(address",
        "delegatecall(",
    ),
    "approval_spender": (
        "transferFrom(",
        "safeTransferFrom(",
        "approve(",
        "permit(",
    ),
    "bridge_receiver": (
        "lzReceive(",
        "ccipReceive(",
        "receiveMessage(",
        "processMessage(",
    ),
    "reward_settlement": (
        "claim(",
        "claimReward(",
        "settle(",
        "checkpoint(",
    ),
}

_EIP1967_CONSTANTS = {
    "eip1967_implementation_slot": "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "eip1967_admin_slot": "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "eip1967_beacon_slot": "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}

_METADATA_MARKERS = (
    "a264697066735822",  # Solidity CBOR ipfs
    "a265627a7a72315820",  # Solidity CBOR bzzr1
    "a165627a7a72305820",  # old Solidity swarm
)


def normalize_bytecode(bytecode: str | None) -> str:
    h = (bytecode or "").lower().strip()
    if h.startswith("0x"):
        h = h[2:]
    h = re.sub(r"[^0-9a-f]", "", h)
    if len(h) % 2:
        h = h[:-1]
    return h


def strip_metadata(code_hex: str) -> tuple[str, str | None]:
    markers = [(code_hex.find(marker), marker) for marker in _METADATA_MARKERS if marker in code_hex]
    markers = [(idx, marker) for idx, marker in markers if idx > 0]
    if not markers:
        return code_hex, None
    idx, marker = min(markers, key=lambda item: item[0])
    return code_hex[:idx], marker


def iter_opcodes(code_hex: str) -> list[dict]:
    ops: list[dict] = []
    i = 0
    n = len(code_hex)
    while i + 2 <= n:
        pc = i // 2
        opcode = int(code_hex[i : i + 2], 16)
        i += 2
        name = _OPCODES.get(opcode, f"UNKNOWN_{opcode:02x}")
        push_data = ""
        if 0x60 <= opcode <= 0x7F:
            push_len = opcode - 0x5F
            push_data = code_hex[i : i + push_len * 2]
            i += push_len * 2
        elif opcode == 0x5F:
            push_data = ""
        ops.append({"pc": pc, "opcode": opcode, "name": name, "push_data": push_data})
    return ops


def _runtime_hash(code_hex: str) -> str:
    if not code_hex:
        return ""
    return "0x" + keccak(bytes.fromhex(code_hex)).hex()


def detect_minimal_proxy(code_hex: str) -> str | None:
    marker = "363d3d373d3d3d363d73"
    idx = code_hex.find(marker)
    if idx < 0:
        return None
    start = idx + len(marker)
    addr = code_hex[start : start + 40]
    if len(addr) != 40:
        return None
    try:
        if int(addr, 16) == 0:
            return None
    except ValueError:
        return None
    return "0x" + addr


def _extract_selectors(ops: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for op in ops:
        if op["name"] != "PUSH4":
            continue
        selector = op.get("push_data", "")
        if len(selector) != 8 or selector in seen:
            continue
        seen.add(selector)
        out.append(
            {
                "selector": "0x" + selector,
                "pc": op["pc"],
                "signatures": KNOWN_SELECTORS.get(selector, []),
            }
        )
    return out


def _selector_clusters(selectors: list[dict]) -> dict[str, list[str]]:
    clusters: dict[str, list[str]] = {k: [] for k in _SELECTOR_CLUSTERS}
    for item in selectors:
        for sig in item.get("signatures") or []:
            for cluster, prefixes in _SELECTOR_CLUSTERS.items():
                if any(sig.startswith(prefix) for prefix in prefixes):
                    clusters[cluster].append(sig)
    return {k: sorted(set(v)) for k, v in clusters.items() if v}


def _constants(code_hex: str, ops: list[dict]) -> dict:
    present_slots = [
        name for name, slot in _EIP1967_CONSTANTS.items() if slot in code_hex
    ]
    push32 = []
    for op in ops:
        if op["name"] == "PUSH32" and len(op.get("push_data", "")) == 64:
            push32.append("0x" + op["push_data"])
    return {
        "eip1967_slots_present": present_slots,
        "push32_sample": push32[:24],
        "push32_count": len(push32),
    }


def _risk(
    rule_id: str,
    title: str,
    severity: str,
    confidence: float,
    description: str,
    *,
    evidence: dict | None = None,
    next_tests: list[str] | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "evidence": evidence or {},
        "next_tests": next_tests or [],
    }


def _risk_signals(
    *,
    opcode_counts: Counter,
    clusters: dict[str, list[str]],
    constants: dict,
    source_verified: bool,
    minimal_proxy_target: str | None,
) -> list[dict]:
    signals: list[dict] = []
    delegatecalls = opcode_counts.get("DELEGATECALL", 0)
    calls = opcode_counts.get("CALL", 0)

    if delegatecalls and clusters.get("arbitrary_execution"):
        signals.append(_risk(
            "closed_source_delegatecall_executor",
            "Closed-source delegatecall/executor bytecode cluster",
            "critical",
            6.0 if not source_verified else 4.0,
            (
                "Runtime bytecode contains DELEGATECALL and public executor-style selectors. "
                "Without verified source, target/selector allowlists and auth context cannot be "
                "confirmed from Solidity."
            ),
            evidence={
                "delegatecall_count": delegatecalls,
                "selectors": clusters.get("arbitrary_execution", []),
                "source_verified": source_verified,
            },
            next_tests=[
                "Resolve the selector dispatch and confirm every executor path has caller, target, value, and selector allowlists.",
                "Read live owner/admin/operator state and test an unprivileged fork call with benign calldata before attempting exploit-specific calldata.",
            ],
        ))

    if opcode_counts.get("CALLCODE", 0):
        signals.append(_risk(
            "legacy_callcode_runtime",
            "Legacy CALLCODE opcode present in deployed runtime",
            "critical",
            5.5,
            "CALLCODE is a legacy delegatecall-equivalent edge that can preserve caller/value context unexpectedly.",
            evidence={"callcode_count": opcode_counts.get("CALLCODE", 0)},
            next_tests=[
                "Decompile the CALLCODE path and identify whether the callee address is user-controlled or upgrade/admin controlled.",
                "Prefer a fork trace over source assumptions; CALLCODE-era contracts often predate modern access-control conventions.",
            ],
        ))

    if opcode_counts.get("ORIGIN", 0) and (opcode_counts.get("SSTORE", 0) or calls):
        signals.append(_risk(
            "tx_origin_mutable_flow",
            "Runtime uses tx.origin in a mutable/external-call flow",
            "high",
            5.5,
            "Bytecode contains ORIGIN plus state writes or external calls, a classic phishing/provenance bypass surface.",
            evidence={
                "origin_count": opcode_counts.get("ORIGIN", 0),
                "sstore_count": opcode_counts.get("SSTORE", 0),
                "call_count": calls,
            },
            next_tests=[
                "Locate the ORIGIN comparison in disassembly/decompiler output and confirm whether it gates privileged state or value movement.",
                "Fork-test a phishing-style intermediate caller if the target trusts tx.origin.",
            ],
        ))

    if clusters.get("approval_spender") and calls:
        signals.append(_risk(
            "closed_source_approval_spender",
            "Closed-source approval-spender/router selector cluster",
            "high",
            5.0 if not source_verified else 3.5,
            (
                "Runtime bytecode exposes transferFrom/permit/approve-like selectors and performs external CALLs. "
                "For an unverified router or spender, standing user approvals can become drain impact if "
                "target/calldata routing is weak."
            ),
            evidence={"selectors": clusters.get("approval_spender", []), "call_count": calls},
            next_tests=[
                "Check token approval exposure to this address and whether any public router path can choose from/to/amount.",
                "Map selector dispatch and require target/token allowlists before downgrading.",
            ],
        ))

    if clusters.get("upgrade_admin") and (
        constants.get("eip1967_slots_present") or opcode_counts.get("DELEGATECALL", 0)
    ):
        signals.append(_risk(
            "unverified_upgrade_surface",
            "Upgradeable/proxy bytecode surface without source-level auth proof",
            "high",
            4.5 if not source_verified else 3.0,
            (
                "Bytecode exposes upgrade/admin/initializer selectors and proxy/delegatecall constants. "
                "If the implementation or proxy admin is unverified, initializer and upgrade auth must be "
                "proved from live state and bytecode, not source assumptions."
            ),
            evidence={
                "selectors": clusters.get("upgrade_admin", []),
                "eip1967_slots_present": constants.get("eip1967_slots_present", []),
            },
            next_tests=[
                "Read EIP-1967 implementation/admin slots and admin owner; compare explorer-reported implementation with live slot.",
                "Try read-only fork calls for initializer/reinitializer and upgrade selectors from an unprivileged address.",
            ],
        ))

    if opcode_counts.get("SELFDESTRUCT", 0):
        signals.append(_risk(
            "selfdestruct_runtime_surface",
            "SELFDESTRUCT opcode present in deployed runtime",
            "high",
            4.5,
            "Runtime bytecode contains SELFDESTRUCT. This can be intended cleanup, but in unverified bytecode it needs auth and reachability proof.",
            evidence={"selfdestruct_count": opcode_counts.get("SELFDESTRUCT", 0)},
            next_tests=[
                "Locate the SELFDESTRUCT dispatch path and prove it is unreachable or restricted to a documented trusted role.",
                "For proxy/clone patterns, check whether delegatecall can execute this opcode in another storage context.",
            ],
        ))

    if minimal_proxy_target and not source_verified:
        signals.append(_risk(
            "minimal_proxy_unverified_impl",
            "Minimal proxy points to bytecode-only implementation",
            "medium",
            4.0,
            "EIP-1167 clone bytecode was detected; the scanner must audit the implementation target, not only the clone shell.",
            evidence={"implementation": minimal_proxy_target},
            next_tests=[
                "Fetch and scan the implementation target directly with Ultra Deep V2.",
                "Check whether the clone factory initializes owner/admin state per clone or leaves shared mutable state.",
            ],
        ))

    return signals


def analyze_bytecode(
    bytecode: str | None,
    *,
    address: str = "",
    chain: str = "",
    source_verified: bool = False,
    proxy_info: dict | None = None,
) -> dict:
    code = normalize_bytecode(bytecode)
    stripped, metadata_marker = strip_metadata(code)
    ops = iter_opcodes(stripped)
    opcode_counts = Counter(op["name"] for op in ops)
    selectors = _extract_selectors(ops)
    clusters = _selector_clusters(selectors)
    constants = _constants(stripped, ops)
    minimal_proxy_target = detect_minimal_proxy(stripped)
    risks = _risk_signals(
        opcode_counts=opcode_counts,
        clusters=clusters,
        constants=constants,
        source_verified=source_verified,
        minimal_proxy_target=minimal_proxy_target,
    )
    return {
        "address": address,
        "chain": chain,
        "source_verified": source_verified,
        "code_size_bytes": len(code) // 2,
        "stripped_code_size_bytes": len(stripped) // 2,
        "runtime_keccak": _runtime_hash(code),
        "stripped_runtime_keccak": _runtime_hash(stripped),
        "metadata_marker": metadata_marker,
        "proxy_info": proxy_info or {},
        "minimal_proxy_target": minimal_proxy_target,
        "opcode_counts": dict(sorted(opcode_counts.items())),
        "selectors": selectors,
        "known_selectors": [s for s in selectors if s.get("signatures")],
        "selector_clusters": clusters,
        "constants": constants,
        "risk_signals": risks,
        "decompiler_summary": _decompiler_summary(opcode_counts, clusters, constants, minimal_proxy_target),
    }


def _decompiler_summary(
    opcode_counts: Counter,
    clusters: dict[str, list[str]],
    constants: dict,
    minimal_proxy_target: str | None,
) -> list[str]:
    lines: list[str] = []
    if minimal_proxy_target:
        lines.append(f"EIP-1167 minimal proxy shell; implementation candidate {minimal_proxy_target}.")
    if clusters:
        lines.append(
            "Selector clusters: "
            + "; ".join(f"{name}={', '.join(values)}" for name, values in sorted(clusters.items()))
        )
    danger_ops = [
        op for op in ("DELEGATECALL", "CALLCODE", "SELFDESTRUCT", "ORIGIN", "EXTCODESIZE", "CREATE2")
        if opcode_counts.get(op)
    ]
    if danger_ops:
        lines.append(
            "Risk opcodes: "
            + ", ".join(f"{op} x{opcode_counts[op]}" for op in danger_ops)
        )
    slots = constants.get("eip1967_slots_present") or []
    if slots:
        lines.append("EIP-1967 slot constants present: " + ", ".join(slots))
    if not lines:
        lines.append("No high-signal bytecode-only cluster matched.")
    return lines


def disassembly_preview(bytecode: str | None, *, max_ops: int = 400) -> str:
    code = normalize_bytecode(bytecode)
    stripped, _marker = strip_metadata(code)
    lines = []
    for op in iter_opcodes(stripped)[:max_ops]:
        arg = f" 0x{op['push_data']}" if op.get("push_data") else ""
        lines.append(f"{op['pc']:06x}: {op['name']}{arg}")
    if len(iter_opcodes(stripped)) > max_ops:
        lines.append(f"... truncated after {max_ops} opcodes")
    return "\n".join(lines)


def run_bytecode_intel(
    *,
    bytecode: str | None,
    out_dir: Path,
    address: str = "",
    chain: str = "",
    source_verified: bool = False,
    proxy_info: dict | None = None,
) -> RunnerResult:
    code = normalize_bytecode(bytecode)
    if not code:
        return RunnerResult.skipped(TOOL_NAME, "no deployed runtime bytecode")

    out_dir.mkdir(parents=True, exist_ok=True)
    report = analyze_bytecode(
        bytecode,
        address=address,
        chain=chain,
        source_verified=source_verified,
        proxy_info=proxy_info,
    )
    json_path = out_dir / "bytecode_intel.json"
    disasm_path = out_dir / "disassembly.txt"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    disasm_path.write_text(disassembly_preview(bytecode), encoding="utf-8")

    risks = report.get("risk_signals") or []
    findings = [
        {
            "check": r["rule_id"],
            "impact": r["severity"],
            "confidence": r["confidence"],
            "description": r["description"],
            "location": "runtime bytecode",
        }
        for r in risks
    ]
    summary = (
        f"bytecode-intel: {report['code_size_bytes']} byte runtime, "
        f"{len(report['selectors'])} PUSH4 selector(s), {len(risks)} risk signal(s)"
    )
    return RunnerResult(
        tool_name=TOOL_NAME,
        status="ok",
        json_output_path=str(json_path),
        stdout_path=str(disasm_path),
        summary=summary,
        findings=findings,
        meta=report,
    )
