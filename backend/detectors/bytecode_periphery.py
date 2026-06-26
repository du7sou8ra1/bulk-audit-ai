"""Ultra Deep V2 bytecode-only periphery detector.

Source detectors are stronger when verified Solidity exists. This detector is
for the gap in between: deployed runtime bytecode exists, source is missing or
source/implementation provenance is not enough, and bytecode-intel has found a
cluster that historically maps to high-impact periphery bugs.
"""
from __future__ import annotations

from ..core.bytecode_intel import analyze_bytecode
from .base import Detector, FindingCandidate, TargetContext


_IMPACT_BY_RULE = {
    "closed_source_delegatecall_executor": 9.0,
    "legacy_callcode_runtime": 9.0,
    "tx_origin_mutable_flow": 8.0,
    "closed_source_approval_spender": 8.5,
    "unverified_upgrade_surface": 8.0,
    "selfdestruct_runtime_surface": 7.5,
    "minimal_proxy_unverified_impl": 5.5,
}

_SEVERITY_BY_RULE = {
    "closed_source_delegatecall_executor": "critical",
    "legacy_callcode_runtime": "critical",
    "tx_origin_mutable_flow": "high",
    "closed_source_approval_spender": "high",
    "unverified_upgrade_surface": "high",
    "selfdestruct_runtime_surface": "high",
    "minimal_proxy_unverified_impl": "medium",
}

_SOURCE_VERIFIED_SAFE_RULES = {
    "closed_source_delegatecall_executor",
    "legacy_callcode_runtime",
    "tx_origin_mutable_flow",
}


class BytecodePeripheryDetector(Detector):
    name = "bytecode_periphery"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        intel_out = ctx.tool_outputs.get("bytecode-intel") or {}
        meta = intel_out.get("meta")
        if not meta:
            meta = analyze_bytecode(
                ctx.bytecode,
                address=ctx.address,
                chain=ctx.chain,
                source_verified=bool(ctx.source_files),
                proxy_info=ctx.proxy_info.to_dict() if ctx.proxy_info else {},
            )

        if not meta or not meta.get("code_size_bytes"):
            return []

        source_verified = bool(meta.get("source_verified") or ctx.source_files)
        out: list[FindingCandidate] = []
        for signal in meta.get("risk_signals") or []:
            rule_id = signal.get("rule_id", "")
            if source_verified and rule_id not in _SOURCE_VERIFIED_SAFE_RULES:
                continue
            if rule_id == "minimal_proxy_unverified_impl" and ctx.proxy_info and ctx.proxy_info.implementation:
                # The normal proxy resolver already found the impl; this stays as
                # bytecode intel, not a finding, unless source is missing there too.
                continue

            impact = _IMPACT_BY_RULE.get(rule_id, 7.0)
            conf = float(signal.get("confidence") or 4.0)
            evidence = {
                "source": self.name,
                "rule_id": rule_id,
                "bug_class": "bytecode_unverified_periphery",
                "onchain_detectable": "confirmable",
                "needs_poc": True,
                "lead_only": True,
                "has_access_control": False,
                "bytecode_intel": {
                    "runtime_keccak": meta.get("runtime_keccak"),
                    "stripped_runtime_keccak": meta.get("stripped_runtime_keccak"),
                    "code_size_bytes": meta.get("code_size_bytes"),
                    "source_verified": source_verified,
                    "selector_clusters": meta.get("selector_clusters", {}),
                    "known_selectors": meta.get("known_selectors", [])[:16],
                    "opcode_counts": _interesting_opcode_counts(meta.get("opcode_counts", {})),
                    "minimal_proxy_target": meta.get("minimal_proxy_target"),
                    "risk_signal": signal,
                    "decompiler_summary": meta.get("decompiler_summary", []),
                },
            }
            out.append(FindingCandidate(
                detector=self.name,
                title=signal.get("title") or f"Bytecode periphery risk: {rule_id}",
                description=signal.get("description") or "Bytecode-only risk cluster detected.",
                impact_score=impact,
                confidence_score=conf,
                severity_candidate=_SEVERITY_BY_RULE.get(rule_id, "high"),
                evidence=evidence,
                next_tests=signal.get("next_tests") or [
                    "Run a focused decompiler/fork trace on the bytecode dispatch path.",
                    "Resolve live owner/admin/operator state before claiming exploitability.",
                ],
                affected_functions=[rule_id],
            ))
        return out


def _interesting_opcode_counts(counts: dict) -> dict:
    interesting = (
        "CALL",
        "DELEGATECALL",
        "CALLCODE",
        "SELFDESTRUCT",
        "ORIGIN",
        "SSTORE",
        "EXTCODESIZE",
        "EXTCODEHASH",
        "CREATE",
        "CREATE2",
    )
    return {op: counts.get(op, 0) for op in interesting if counts.get(op, 0)}
