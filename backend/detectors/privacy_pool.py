"""Privacy-pool / mixer invariant detector.

This detector intentionally focuses on invariants that are visible in Solidity:
nullifier replay marking, Merkle-root anchoring, proof/public-input binding, and
withdrawal fee bounds. It uses the Phase 8 semantic index when present so it can
reason over state writes and value sinks instead of relying only on raw text.
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments
from ..core.semantic_index import ContractFacts, FunctionFacts, build_semantic_index

_PRIVACY_HINT_RE = re.compile(
    r"nullifier|commitment|mixer|privacy|withdraw|relayer|denomination|"
    r"merkle|root|isKnownRoot|verifyProof|publicInput|publicSignals|proof",
    re.I,
)
_PROOF_RE = re.compile(r"verify\w*\s*\(|\bproof\b|publicInputs?|publicSignals?|snark|groth|plonk", re.I)
_ROOT_RE = re.compile(r"\b(root|merkleRoot|stateRoot)\b", re.I)
_KNOWN_ROOT_RE = re.compile(
    r"isKnownRoot\s*\(|_isKnownRoot\s*\(|knownRoots?\s*\[|roots\s*\[|"
    r"rootHistory|recentRoots?|currentRoot|require\s*\([^;]*root[^;]*(known|current|valid|==)",
    re.I,
)
_NULLIFIER_NAME_RE = re.compile(r"nullifier|spent|claimed|used|consumed", re.I)
_VALUE_SINK_RE = re.compile(
    r"\.\s*(?:transfer|send|safeTransfer|safeTransferFrom)\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|_mint\s*\(|mint\s*\(",
    re.I,
)
_VERIFY_NAME = r"verif(?:y|yProof|yproof|yTx|ytx|yAndUpdate|yandupdate)\w*"
_HASH_BIND_RE = re.compile(r"(?:abi\.encode\w*|keccak256|sha256|poseidon)\s*\(([^;]*)\)", re.I | re.S)
_FEE_BOUND_RE = re.compile(
    r"require\s*\([^;]*(?:fee|relayerFee)[^;]*(?:<=|<)[^;]*(?:amount|value|denomination|deposit|withdrawal)",
    re.I,
)


def _semantic(ctx: TargetContext) -> ContractFacts:
    facts = getattr(ctx, "semantic", None)
    if facts is not None:
        return facts
    return build_semantic_index(ctx.source_files, ctx.abi)


def _iter_facts(ctx: TargetContext, facts: ContractFacts) -> Iterable[FunctionFacts]:
    if facts.functions_by_key:
        yield from facts.functions_by_key.values()
        return
    for path, source in ctx.source_files.items():
        clean = strip_comments(source or "")
        for name, params, tail, body in iter_function_bodies(clean):
            yield FunctionFacts(
                name=name,
                file=path,
                line=1,
                params=[{"name": n, "type": "", "raw": n} for n in _param_names(params)],
                tail=tail,
                body=body,
                visibility="external" if re.search(r"\bexternal\b", tail) else "public",
                mutability="view" if re.search(r"\bview\b", tail) else "nonpayable",
                modifiers=[],
            )


def _param_names(params: str) -> list[str]:
    out: list[str] = []
    for part in (params or "").split(","):
        toks = re.findall(r"[A-Za-z_]\w*", part)
        if toks:
            out.append(toks[-1])
    return out


def _binding_text(body: str) -> str:
    chunks: list[str] = []
    for m in re.finditer(_VERIFY_NAME + r"\s*\(([^;]*)\)", body, re.I | re.S):
        chunks.append(m.group(1))
    for m in re.finditer(r"\[([^\];]*)\]", body):
        inner = m.group(1)
        if "," in inner or "(" in inner:
            chunks.append(inner)
    chunks.extend(m.group(1) for m in _HASH_BIND_RE.finditer(body))
    return " ".join(chunks).lower()


def _word(token: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(token) + r"\b", re.I)


def _write_positions(body: str, var: str) -> list[int]:
    n = re.escape(var)
    patterns = (
        rf"\bdelete\s+{n}\b",
        rf"\b{n}\s*(?:\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|%=|\+\+|--)",
        rf"\b{n}\s*\.\s*(?:push|pop)\s*\(",
    )
    out: list[int] = []
    for pat in patterns:
        out.extend(m.start() for m in re.finditer(pat, body, re.I | re.S))
    return out


def _sink_positions(fn: FunctionFacts) -> list[int]:
    positions = [int(row.get("position", 0)) for row in fn.value_sinks if "position" in row]
    positions.extend(m.start() for m in _VALUE_SINK_RE.finditer(fn.body))
    return sorted(set(positions))


def _critical_params(fn: FunctionFacts) -> list[str]:
    names = [p.get("name", "") for p in fn.params if p.get("name")]
    names.extend(sorted(getattr(fn, "decoded_fields", set()) or set()))
    out: list[str] = []
    for name in names:
        if re.search(r"recipient|receiver|to$|amount|value|fee|relayer|root|nullifier|commitment|denomination", name, re.I):
            out.append(name)
    return sorted(set(out))


def _has_spent_check(body: str, var: str) -> bool:
    return bool(
        re.search(r"require\s*\([^;]*!\s*" + re.escape(var) + r"\s*\[", body, re.I | re.S)
        or re.search(r"require\s*\([^;]*" + re.escape(var) + r"\s*\[[^;]*(?:==\s*false|!=\s*true)", body, re.I | re.S)
        or re.search(r"(?:already|spent|used|nullifier)", body, re.I) and re.search(r"revert|require", body, re.I)
    )


def _fee_names(fn: FunctionFacts) -> tuple[str | None, str | None, str | None]:
    fee = amount = relayer = None
    for p in fn.params:
        name = p.get("name", "")
        if not name:
            continue
        if fee is None and re.search(r"fee", name, re.I):
            fee = name
        if amount is None and re.search(r"amount|value|denomination|deposit", name, re.I):
            amount = name
        if relayer is None and re.search(r"relayer|executor|feeRecipient", name, re.I):
            relayer = name
    return fee, amount, relayer


def _is_privacy_function(fn: FunctionFacts) -> bool:
    text = fn.name + " " + fn.tail + " " + fn.body
    if not _PRIVACY_HINT_RE.search(text):
        return False
    strong = sum(1 for pat in (r"nullifier", r"\broot\b", r"\bproof\b", r"verif", r"relayer|denomination") if re.search(pat, text, re.I))
    return strong >= 2 or bool(re.search(r"withdraw|claim|exit", fn.name, re.I) and _PROOF_RE.search(text))


class PrivacyPoolDetector(Detector):
    name = "privacy_pool"
    profiles = None

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        facts = _semantic(ctx)
        findings: list[FindingCandidate] = []

        for fn in _iter_facts(ctx, facts):
            if not _is_privacy_function(fn):
                continue
            body = fn.body
            binding = _binding_text(body)
            sinks = _sink_positions(fn)
            has_value_sink = bool(sinks or _VALUE_SINK_RE.search(body))

            replay_vars = sorted(v for v in (fn.writes or set()) if _NULLIFIER_NAME_RE.search(v))
            if not replay_vars:
                replay_vars = sorted(set(re.findall(r"\b(\w*(?:nullifier|spent|claimed|used|consumed)\w*)\s*\[", body, re.I)))
            for var in replay_vars:
                writes = _write_positions(body, var)
                if has_value_sink and writes and sinks and any(sink < write for sink in sinks for write in writes):
                    findings.append(self._finding(
                        "privacy_nullifier_marked_after_value_transfer",
                        f"Nullifier/replay marker is written after value transfer: {fn.name}",
                        f"`{fn.name}` moves value before writing `{var}`. A malicious recipient/token hook can reenter before the nullifier is consumed and replay the withdrawal/claim.",
                        9.0, 7.0, "critical", "privacy_pool_nullifier_ordering", fn,
                        tests=[
                            "Use a receiver/token hook to reenter withdraw/claim before the nullifier write executes.",
                            "Move the nullifier/spent write before all external value transfers and retest.",
                        ],
                        extra={"replay_var": var, "semantic_order": True},
                        lead_only=False,
                    ))
                if writes and has_value_sink and not _has_spent_check(body, var):
                    findings.append(self._finding(
                        "privacy_nullifier_written_without_spent_check",
                        f"Nullifier/replay marker is written without a visible spent check: {fn.name}",
                        f"`{fn.name}` writes `{var}` while moving value, but no visible `require(!{var}[...])`/used check precedes it. Reusing a valid proof/nullifier may double-withdraw.",
                        8.5, 6.0, "high", "privacy_pool_nullifier_replay", fn,
                        tests=["Call withdraw/claim twice with the same proof/nullifier on a fork or unit harness."],
                        extra={"replay_var": var},
                        lead_only=False,
                    ))

            if _ROOT_RE.search(" ".join(p.get("name", "") for p in fn.params)) and _PROOF_RE.search(body):
                if not _KNOWN_ROOT_RE.search(body) and not _KNOWN_ROOT_RE.search("\n".join(ctx.source_files.values())):
                    findings.append(self._finding(
                        "privacy_unknown_root_acceptance",
                        f"Proof path accepts a root without a known-root check: {fn.name}",
                        f"`{fn.name}` uses a caller-supplied root in a proof path but no `isKnownRoot(root)`/roots-history/current-root gate is visible. An attacker may prove against a tree they control.",
                        9.0, 6.0, "high", "privacy_pool_root_anchoring", fn,
                        tests=["Submit a proof against an arbitrary/unseen root and confirm it is rejected."],
                        extra={"semantic_root_check": False},
                        lead_only=False,
                    ))

            if _PROOF_RE.search(body) and has_value_sink:
                missing = []
                sink_region = body[min(sinks):] if sinks else body
                for name in _critical_params(fn):
                    if _word(name).search(sink_region) and not _word(name).search(binding):
                        missing.append(name)
                if missing:
                    findings.append(self._finding(
                        "privacy_public_inputs_do_not_bind_action_values",
                        f"Privacy withdrawal acts on values not bound to proof inputs: {fn.name}",
                        f"`{fn.name}` verifies a proof but then acts on {', '.join(missing)} without those names appearing in the visible verify/public-input/hash binding text. This is a proof-to-value binding lead.",
                        8.5, 4.5, "high", "privacy_pool_public_input_binding", fn,
                        tests=[
                            "Confirm each missing value is a circuit public input at the expected index.",
                            "Mutate the missing value while reusing the same proof in a local harness.",
                        ],
                        extra={"missing_bindings": missing, "lead_only": True},
                    ))

            fee, amount, relayer = _fee_names(fn)
            if fee and amount and has_value_sink and re.search(r"\b" + re.escape(fee) + r"\b", body):
                fee_bound = bool(_FEE_BOUND_RE.search(body) or re.search(r"\b" + re.escape(fee) + r"\s*<=\s*" + re.escape(amount), body, re.I))
                fee_bound_to_proof = bool(_word(fee).search(binding))
                if not fee_bound and not fee_bound_to_proof:
                    findings.append(self._finding(
                        "privacy_fee_unbounded_and_not_proof_bound",
                        f"Relayer/withdrawal fee is neither bounded nor proof-bound: {fn.name}",
                        f"`{fn.name}` uses caller-supplied `{fee}` with `{amount}` but no visible `fee <= amount/denomination` guard and `{fee}` is not in the visible proof binding. A relayer can overclaim or force underflow/zero recipient payout.",
                        8.0, 5.0, "high", "privacy_pool_fee_bounds", fn,
                        tests=[f"Set `{fee}` equal to or above `{amount}` and check relayer/recipient payouts."],
                        extra={"fee": fee, "amount": amount, "relayer": relayer},
                    ))

        return self._dedup(findings)

    @staticmethod
    def _finding(
        rule_id: str,
        title: str,
        desc: str,
        impact: float,
        conf: float,
        sev: str,
        bug_class: str,
        fn: FunctionFacts,
        *,
        tests: list[str],
        extra: dict | None = None,
        lead_only: bool = True,
    ) -> FindingCandidate:
        ev = {
            "source": "privacy_pool",
            "rule_id": rule_id,
            "bug_class": bug_class,
            "file": fn.file,
            "line": fn.line,
            "snippet": (fn.tail + "\n" + fn.body)[:2400],
            "needs_poc": True,
            "needs_stateful_poc": True,
            "semantic_facts": True,
            "onchain_detectable": "lead_only" if lead_only else "confirmable",
        }
        if lead_only:
            ev["lead_only"] = True
        if extra:
            ev.update(extra)
        return FindingCandidate(
            detector="privacy_pool",
            title=title,
            description=desc,
            impact_score=impact,
            confidence_score=conf,
            severity_candidate=sev,
            evidence=ev,
            next_tests=tests,
            affected_functions=[fn.name],
        )

    @staticmethod
    def _dedup(findings: list[FindingCandidate]) -> list[FindingCandidate]:
        seen: set[tuple[str, str]] = set()
        out: list[FindingCandidate] = []
        for finding in findings:
            key = (str(finding.evidence.get("rule_id")), (finding.affected_functions or [""])[0])
            if key in seen:
                continue
            seen.add(key)
            out.append(finding)
        return out
