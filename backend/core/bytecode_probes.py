"""Selector-specific probe planning for bytecode-only findings.

Phase 6 tells us *what* bytecode cluster exists. Phase 7 turns that into the
next validation step: deterministic probe cases, safe cast commands, and a
Foundry fork scaffold that an auditor can run against a fork without private
keys or live transactions.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..runners.base import RunnerResult


TOOL_NAME = "bytecode-probes"


_SIGNATURE_ARGS = {
    "admin()": (),
    "implementation()": (),
    "proxiableUUID()": (),
    "initialize()": (),
    "initialize(address)": ("address",),
    "initialize(address,address)": ("address", "address"),
    "reinitialize(uint8)": ("uint8",),
    "upgradeTo(address)": ("address",),
    "upgradeToAndCall(address,bytes)": ("address", "bytes"),
    "changeAdmin(address)": ("address",),
    "execute(address,uint256,bytes)": ("address", "uint256", "bytes"),
    "execute(bytes)": ("bytes",),
    "execute(bytes[])": ("bytes[]",),
    "executeBatch(address[],uint256[],bytes[])": ("address[]", "uint256[]", "bytes[]"),
    "multicall(bytes[])": ("bytes[]",),
    "aggregate((address,bytes)[])": ("tuple[]",),
    "call(address,uint256,bytes)": ("address", "uint256", "bytes"),
    "delegatecall(address,bytes)": ("address", "bytes"),
    "transferFrom(address,address,uint256)": ("address", "address", "uint256"),
    "safeTransferFrom(address,address,uint256)": ("address", "address", "uint256"),
    "safeTransferFrom(address,address,uint256,bytes)": ("address", "address", "uint256", "bytes"),
    "approve(address,uint256)": ("address", "uint256"),
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)": (
        "address",
        "address",
        "uint256",
        "uint256",
        "uint8",
        "bytes32",
        "bytes32",
    ),
    "claim()": (),
    "claim(address)": ("address",),
    "claimReward(address)": ("address",),
    "settle()": (),
    "settle(address)": ("address",),
    "checkpoint()": (),
    "lzReceive(uint16,bytes,uint64,bytes)": ("uint16", "bytes", "uint64", "bytes"),
    "receiveMessage(bytes)": ("bytes",),
    "processMessage(bytes)": ("bytes",),
}


_RULE_FOCUS = {
    "closed_source_delegatecall_executor": {
        "kind": "executor",
        "clusters": ("arbitrary_execution",),
        "goal": "Prove whether an unprivileged caller can reach arbitrary call/delegatecall execution.",
        "must_fail": False,
    },
    "legacy_callcode_runtime": {
        "kind": "legacy-callcode",
        "clusters": ("arbitrary_execution",),
        "goal": "Resolve CALLCODE reachability and whether the callee is user or admin controlled.",
        "must_fail": False,
    },
    "tx_origin_mutable_flow": {
        "kind": "tx-origin",
        "clusters": ("upgrade_admin", "approval_spender", "arbitrary_execution"),
        "goal": "Locate selector paths that combine tx.origin with state mutation or external calls.",
        "must_fail": False,
    },
    "closed_source_approval_spender": {
        "kind": "approval-drain",
        "clusters": ("approval_spender", "arbitrary_execution"),
        "goal": "Check whether public spender/router selectors can choose victim, receiver, token, or amount.",
        "must_fail": False,
    },
    "unverified_upgrade_surface": {
        "kind": "upgrade-auth",
        "clusters": ("upgrade_admin",),
        "goal": "Probe whether initializer or upgrade selectors reject unprivileged callers on a fork.",
        "must_fail": True,
    },
    "selfdestruct_runtime_surface": {
        "kind": "selfdestruct",
        "clusters": ("upgrade_admin", "arbitrary_execution"),
        "goal": "Find dispatch paths that could reach SELFDESTRUCT directly or via delegatecall.",
        "must_fail": False,
    },
    "minimal_proxy_unverified_impl": {
        "kind": "clone-implementation",
        "clusters": ("upgrade_admin", "arbitrary_execution", "approval_spender"),
        "goal": "Scan the implementation target and verify per-clone initialization state.",
        "must_fail": False,
    },
}


def build_probe_plan(
    bytecode_meta: dict,
    *,
    address: str = "",
    chain: str = "",
    rpc_env_var: str | None = None,
) -> dict:
    """Build a deterministic selector probe plan from bytecode-intel metadata."""
    address = _normalize_address(address or bytecode_meta.get("address") or "")
    chain = chain or bytecode_meta.get("chain") or ""
    rpc_env_var = rpc_env_var or _rpc_env_for_chain(chain)
    signals = bytecode_meta.get("risk_signals") or []
    clusters = bytecode_meta.get("selector_clusters") or {}
    known_selectors = bytecode_meta.get("known_selectors") or []

    probes: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for signal in signals:
        rule_id = signal.get("rule_id", "")
        focus = _RULE_FOCUS.get(rule_id, {})
        signatures = _signatures_for_focus(focus, clusters, known_selectors)
        if not signatures and rule_id in ("legacy_callcode_runtime", "selfdestruct_runtime_surface"):
            signatures = ["<unknown-dispatch>"]
        for sig in signatures[:8]:
            key = (rule_id, sig)
            if key in seen:
                continue
            seen.add(key)
            probes.append(_probe_case(rule_id, sig, focus, address, chain, rpc_env_var))

    return {
        "suite": "elite-phase-7-bytecode-selector-probes",
        "address": address,
        "chain": chain,
        "rpc_env_var": rpc_env_var,
        "runtime_keccak": bytecode_meta.get("runtime_keccak"),
        "stripped_runtime_keccak": bytecode_meta.get("stripped_runtime_keccak"),
        "code_size_bytes": bytecode_meta.get("code_size_bytes"),
        "risk_signal_count": len(signals),
        "probe_count": len(probes),
        "probes": probes,
        "operator_notes": [
            "Run these only on a local fork or with eth_call/cast call; never send live transactions.",
            "A successful unprivileged upgrade or privileged mutation probe is a critical lead, not a complete report until impact is traced.",
            "A revert is not an automatic kill: inspect the revert reason, caller provenance, and whether another selector reaches the same sink.",
        ],
    }


def run_bytecode_probes(
    *,
    bytecode_meta: dict | None,
    out_dir: Path,
    address: str = "",
    chain: str = "",
    rpc_env_var: str | None = None,
) -> RunnerResult:
    if not bytecode_meta:
        return RunnerResult.skipped(TOOL_NAME, "bytecode-intel metadata unavailable")
    if not bytecode_meta.get("risk_signals"):
        return RunnerResult.skipped(TOOL_NAME, "no bytecode risk signals to probe")

    plan = build_probe_plan(
        bytecode_meta,
        address=address,
        chain=chain,
        rpc_env_var=rpc_env_var,
    )
    if not plan["probes"]:
        return RunnerResult.skipped(TOOL_NAME, "bytecode risks had no selector-specific probes")

    out_dir.mkdir(parents=True, exist_ok=True)
    plan_path = out_dir / "probe_plan.json"
    md_path = out_dir / "BYTECODE_PROBES.md"
    foundry_dir = out_dir / "foundry"
    test_dir = foundry_dir / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    foundry_path = test_dir / "BytecodeSelectorProbes.t.sol"
    toml_path = foundry_dir / "foundry.toml"

    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_markdown(plan), encoding="utf-8")
    foundry_path.write_text(render_foundry_harness(plan), encoding="utf-8")
    toml_path.write_text('[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\n', encoding="utf-8")

    findings = [
        {
            "check": probe["rule_id"],
            "impact": probe["severity_hint"],
            "confidence": 4.0,
            "description": probe["goal"],
            "location": f"selector {probe['signature']}",
        }
        for probe in plan["probes"]
    ]
    return RunnerResult(
        tool_name=TOOL_NAME,
        status="ok",
        json_output_path=str(plan_path),
        stdout_path=str(md_path),
        summary=f"bytecode-probes: generated {plan['probe_count']} selector probe(s)",
        findings=findings,
        meta={
            **plan,
            "artifact_paths": {
                "plan": str(plan_path),
                "markdown": str(md_path),
                "foundry_harness": str(foundry_path),
                "foundry_toml": str(toml_path),
            },
        },
    )


def render_markdown(plan: dict) -> str:
    lines = [
        "# Elite Phase 7 Bytecode Probes",
        "",
        f"- Target: `{plan['address'] or 'unknown'}`",
        f"- Chain: `{plan['chain'] or 'unknown'}`",
        f"- Runtime hash: `{plan.get('runtime_keccak') or 'unknown'}`",
        f"- Probe count: `{plan['probe_count']}`",
        "",
        "## Safety",
        "",
        "- Use these probes only against a local fork or read-only `cast call`.",
        "- Do not broadcast live transactions.",
        "- Treat success as a lead requiring impact tracing.",
        "",
        "## Commands",
        "",
        "```bash",
        f"cd tools/bytecode-probes/foundry",
        f"{plan['rpc_env_var']}=$RPC_URL forge test -vv",
        "```",
        "",
    ]
    for i, probe in enumerate(plan["probes"], 1):
        lines += [
            f"## Probe {i}: {probe['rule_id']}",
            "",
            f"- Signature: `{probe['signature']}`",
            f"- Goal: {probe['goal']}",
            f"- Expected safe result: {probe['expected_safe_result']}",
            "",
            "```bash",
            probe["cast_call"],
            "```",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def render_foundry_harness(plan: dict) -> str:
    target = _sol_address(plan.get("address") or "0x0000000000000000000000000000000000000000")
    rpc_env = plan.get("rpc_env_var") or "RPC_URL"
    tests = []
    for i, probe in enumerate(plan["probes"]):
        fn = f"test_probe_{i:02d}_{_safe_identifier(probe['rule_id'])}_{_safe_identifier(probe['signature'])}"
        calldata_expr = _sol_calldata_expr(probe["signature"])
        tests.append(
            f"    function {fn}() public {{\n"
            f"        bytes memory data = {calldata_expr};\n"
            f"        (bool ok, bytes memory ret) = TARGET.call(data);\n"
            f"        emit ProbeResult(\"{probe['rule_id']}\", \"{probe['signature']}\", ok, ret.length);\n"
            f"        if ({str(bool(probe.get('must_fail'))).lower()} && ok) {{\n"
            f"            revert(\"unprivileged privileged selector unexpectedly succeeded\");\n"
            f"        }}\n"
            f"    }}\n"
        )
    return (
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.20;\n\n"
        "interface Vm {\n"
        "    function envOr(string calldata key, string calldata defaultValue) external returns (string memory value);\n"
        "    function createSelectFork(string calldata url) external returns (uint256 forkId);\n"
        "}\n\n"
        "contract BytecodeSelectorProbes {\n"
        "    struct Call { address target; bytes callData; }\n\n"
        "    Vm constant vm = Vm(address(uint160(uint256(keccak256(\"hevm cheat code\")))));\n"
        f"    address constant TARGET = {target};\n\n"
        "    event ProbeResult(string rule, string signature, bool ok, uint256 returndataLen);\n\n"
        "    function setUp() public {\n"
        f"        string memory rpc = vm.envOr(\"{rpc_env}\", string(\"\"));\n"
        "        if (bytes(rpc).length != 0) {\n"
        "            vm.createSelectFork(rpc);\n"
        "        }\n"
        "    }\n\n"
        + "\n".join(tests)
        + "}\n"
    )


def _signatures_for_focus(focus: dict, clusters: dict, known_selectors: list[dict]) -> list[str]:
    signatures: list[str] = []
    for cluster in focus.get("clusters") or ():
        signatures.extend(clusters.get(cluster) or [])
    known = [sig for item in known_selectors for sig in (item.get("signatures") or [])]
    if not signatures and known:
        signatures.extend(known)
    return sorted(dict.fromkeys(signatures))


def _probe_case(rule_id: str, signature: str, focus: dict, address: str, chain: str, rpc_env_var: str) -> dict:
    severity = "critical" if rule_id in {"closed_source_delegatecall_executor", "legacy_callcode_runtime"} else "high"
    if rule_id == "minimal_proxy_unverified_impl":
        severity = "medium"
    return {
        "rule_id": rule_id,
        "kind": focus.get("kind", "bytecode"),
        "signature": signature,
        "selector": _selector_from_signature(signature),
        "target": address,
        "chain": chain,
        "rpc_env_var": rpc_env_var,
        "goal": focus.get("goal", "Resolve selector reachability on a fork."),
        "must_fail": bool(focus.get("must_fail")),
        "expected_safe_result": (
            "revert for unprivileged caller"
            if focus.get("must_fail")
            else "revert or harmless no-op unless authorized pre-state is intentionally supplied"
        ),
        "calldata_template": _cast_calldata_args(signature),
        "cast_call": _cast_call(address, signature, rpc_env_var),
        "severity_hint": severity,
        "next_steps": _next_steps(rule_id, signature),
    }


def _next_steps(rule_id: str, signature: str) -> list[str]:
    common = [
        "Run on a local fork and record success/revert plus returndata length.",
        "If the probe succeeds, inspect state diffs and trace the callee path before promoting.",
    ]
    if rule_id == "unverified_upgrade_surface":
        return [
            "Verify implementation/admin slots before and after the fork probe.",
            "If any initializer/upgrade selector succeeds from an unprivileged caller, trace role takeover or implementation replacement impact.",
        ] + common
    if "transferFrom" in signature or rule_id == "closed_source_approval_spender":
        return [
            "Check live user/token approvals to the target and whether the selector can choose victim/receiver/amount.",
            "Attempt a fork-only zero-amount and nonzero-amount call with attacker-controlled from/to values.",
        ] + common
    if rule_id == "closed_source_delegatecall_executor":
        return [
            "Trace whether target, value, and calldata are caller-controlled.",
            "Check whether delegatecall executes in target storage and can reach token/ETH movement.",
        ] + common
    return common


def _cast_call(address: str, signature: str, rpc_env_var: str) -> str:
    if signature == "<unknown-dispatch>":
        return f"cast code {address or '<target>'} --rpc-url ${rpc_env_var}"
    args = " ".join(_cast_calldata_args(signature))
    spacer = " " if args else ""
    return f"cast call {address or '<target>'} '{signature}'{spacer}{args} --rpc-url ${rpc_env_var}"


def _cast_calldata_args(signature: str) -> list[str]:
    return [_cast_arg(t) for t in _SIGNATURE_ARGS.get(signature, ())]


def _cast_arg(kind: str) -> str:
    if kind == "address":
        return "0x000000000000000000000000000000000000dead"
    if kind == "uint8":
        return "1"
    if kind in ("uint16", "uint64", "uint256"):
        return "0"
    if kind == "bytes32":
        return "0x" + "00" * 32
    if kind == "bytes":
        return "0x"
    if kind == "bytes[]":
        return "[]"
    if kind == "address[]":
        return "[]"
    if kind == "uint256[]":
        return "[]"
    if kind == "tuple[]":
        return "[]"
    return "0"


def _sol_calldata_expr(signature: str) -> str:
    if signature == "<unknown-dispatch>":
        return 'hex""'
    args = ", ".join(_sol_arg(t) for t in _SIGNATURE_ARGS.get(signature, ()))
    if args:
        return f'abi.encodeWithSignature("{signature}", {args})'
    return f'abi.encodeWithSignature("{signature}")'


def _sol_arg(kind: str) -> str:
    if kind == "address":
        return "address(0x000000000000000000000000000000000000dead)"
    if kind == "uint8":
        return "uint8(1)"
    if kind == "uint16":
        return "uint16(0)"
    if kind == "uint64":
        return "uint64(0)"
    if kind == "uint256":
        return "uint256(0)"
    if kind == "bytes32":
        return "bytes32(0)"
    if kind == "bytes":
        return 'hex""'
    if kind == "bytes[]":
        return "new bytes[](0)"
    if kind == "address[]":
        return "new address[](0)"
    if kind == "uint256[]":
        return "new uint256[](0)"
    if kind == "tuple[]":
        return "new Call[](0)"
    return "uint256(0)"


def _selector_from_signature(signature: str) -> str:
    if signature == "<unknown-dispatch>":
        return ""
    from .bytecode_intel import _selector

    return "0x" + _selector(signature)


def _rpc_env_for_chain(chain: str) -> str:
    c = (chain or "").upper().replace("-", "_")
    if c and c != "ETHEREUM":
        return f"RPC_URL_{c}"
    return "RPC_URL"


def _normalize_address(address: str) -> str:
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", address or ""):
        return address
    return ""


def _sol_address(address: str) -> str:
    if not _normalize_address(address):
        address = "0x0000000000000000000000000000000000000000"
    return "address(" + address.lower() + ")"


def _safe_identifier(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_]+", "_", text or "x").strip("_")
    if not text:
        text = "x"
    if text[0].isdigit():
        text = "x_" + text
    return text[:64]
