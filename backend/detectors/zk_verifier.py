"""Detector: ZK-rollup on-chain settlement<->proof binding (gap #7, real).

Replaces the v0.1 stub. It does NOT pretend to audit the circuit — that lives
off-chain (boojum/halo2/circom) and is invisible to a Solidity tool. Instead it
audits the ONE thing that IS on-chain and IS the Aztec/Lighter bug class:

  Does the contract release funds / credit balances from caller-supplied data
  (withdrawal pubdata, exit amounts, recipients) that is bound to a VERIFIED
  proof / commitment / hash-chain — or not?

Sound code recomputes a hash of the caller-supplied data and requires it equals a
proof-committed value (e.g. `onChainPubDataHash == batch.onChainOperationsHash`,
or a `commitment` fed to `verifier.Verify`). If a value-moving "execute/finalize/
exit/perform" function has NO such binding, that is a settlement-bypass candidate.

It always emits one INFO note stating the circuit is out of tool scope, so a ZK
target is never silently "passed".
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, strip_comments

_ZK_MARKERS = ("verifyproof", "verify(", ".verify", "snark", "groth16", "plonk",
               "commitment", "stateroot", "desertverifier", "publicinput", "proof")
_SETTLE_NAMES = ("executebatch", "executebatches", "finalize", "performdesert",
                 "performexit", "processblock", "withdrawdesert", "exit", "claim",
                 "provewithdraw", "_executeonebatch")
_VERIFY_RE = re.compile(r"\bverify\w*\s*\(|verifyProof|\.Verify\s*\(", re.IGNORECASE)
# A binding: recompute-and-compare a hash/commitment of caller data against a
# stored/verified value. Heuristic but matches the real-world sound pattern.
_BIND_RE = re.compile(
    r"(keccak256|sha256)\s*\([^;]*\)\s*[;\n][^;}]*"  # a hash is computed ...
    r"|(operationshash|pubdatahash|commitment|prefixhash|merkleroot|stateroot)\s*"
    r"(!=|==)\s*",  # ... and compared
    re.IGNORECASE,
)
_STORED_CMP_RE = re.compile(
    r"(!=|==)\s*[\w.]*(commitment|operationshash|pubdatahash|prefixhash|root|stateroot)",
    re.IGNORECASE,
)
_EXT_MOVE_RE = re.compile(
    r"increaseBalanceToWithdraw|_mint\s*\(|safeTransfer|\.transfer\s*\(|\.call\s*\{|pendingBalances|balanceToWithdraw",
    re.IGNORECASE,
)


def _iter_bodies(source: str):
    for m in re.finditer(r"function\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{", source):
        start = m.end() - 1
        depth, i = 0, start
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield m.group(1), source[start : i + 1]


class ZkVerifierDetector(Detector):
    name = "zk_verifier"
    profiles = None

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        src = ctx.all_source_text()
        if not src:
            return []
        low = src.lower()
        if sum(1 for mk in _ZK_MARKERS if mk in low) < 3:
            return []  # not a ZK-rollup / proof-verifying contract

        findings: list[FindingCandidate] = []

        # (1) Honesty note: the circuit is out of tool scope. Always emit once.
        findings.append(
            FindingCandidate(
                detector="zk_verifier",
                title="ZK architecture detected — off-chain circuit is OUT of tool scope",
                description=(
                    "This contract verifies zk-SNARK/STARK proofs. The exploitable "
                    "soundness surface (under-constrained signals, public-input binding, "
                    "Fiat-Shamir) lives in the OFF-CHAIN circuit and cannot be assessed by "
                    "a Solidity-only tool — it needs a ZK specialist with the byte-matched "
                    "circuit source. Only the on-chain settlement<->proof binding was checked "
                    "(see other zk_verifier findings, if any)."
                ),
                impact_score=2.0, confidence_score=9.0, severity_candidate="info",
                evidence={"source": "zk_verifier", "documented_centralization": False,
                          "out_of_tool_scope": "off-chain ZK circuit", "informational": True},
                next_tests=["Engage a ZK auditor with the circuit repo @ deployed commit"],
                affected_functions=[],
            )
        )

        # (2) Settlement-binding check on value-moving settlement functions.
        for path, source in ctx.source_files.items():
            if not source:
                continue
            source = strip_comments(source)
            for fname, body in _iter_bodies(source):
                lname = fname.lower()
                if not any(k in lname for k in _SETTLE_NAMES):
                    continue
                if not _EXT_MOVE_RE.search(body):
                    continue  # doesn't move value/credit balances -> skip
                has_verify = bool(_VERIFY_RE.search(body))
                has_binding = bool(_BIND_RE.search(body) or _STORED_CMP_RE.search(body))
                if has_verify or has_binding:
                    continue  # sound pattern present -> not a candidate
                findings.append(
                    FindingCandidate(
                        detector="zk_verifier",
                        title=f"Settlement function moves value with no visible proof/hash binding: {fname}",
                        description=(
                            f"`{fname}` credits balances / moves value but no proof verification "
                            "(`verifier.Verify`) and no recompute-and-compare binding "
                            "(`keccak(...) == storedCommitment/operationsHash/root`) was detected "
                            "in its body. If caller-supplied withdrawal/exit data is NOT bound to a "
                            "verified commitment, an attacker may credit arbitrary withdrawals "
                            "(settlement bypass — the Aztec/Lighter class)."
                        ),
                        impact_score=9.0, confidence_score=4.0, severity_candidate="critical",
                        evidence={
                            "source": "zk_verifier", "function": fname, "file": path,
                            "snippet": body[:1500], "has_verify": has_verify,
                            "has_hash_binding": has_binding, "needs_poc": True,
                            "bug_class": "settlement_binding",
                        },
                        next_tests=[
                            "Confirm caller-supplied pubdata is hashed and compared to a proof-committed value",
                            "Trace whether the verified commitment includes the withdrawal operations hash",
                        ],
                        affected_functions=[fname],
                    )
                )

        # (3) Groth16 verifying-key parameter check (FOOMCASH/Veil): a snarkjs
        # Groth16 Solidity verifier hardcodes the VK points. If gamma == delta, or
        # a VK point is all-zero, the pairing check degenerates and ANY proof can
        # be accepted. The VK is on-chain, so this is checkable from source.
        findings.extend(self._groth16_param_check(src))
        return findings

    @staticmethod
    def _groth16_param_check(src: str) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        # Collect hex/dec constants named like gamma*/delta* VK coordinates.
        const_re = re.compile(
            r"\b(gamma|delta)([a-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+|\d{6,})", re.IGNORECASE
        )
        gamma: list[str] = []
        delta: list[str] = []
        for m in const_re.finditer(src):
            grp = m.group(1).lower()
            val = m.group(3).lower()
            (gamma if grp == "gamma" else delta).append(val)
        if len(gamma) >= 2 and len(delta) >= 2:
            if gamma == delta:
                out.append(FindingCandidate(
                    detector="zk_verifier",
                    title="Groth16 verifying key: gamma == delta (arbitrary proof acceptance)",
                    description=(
                        "The hardcoded Groth16 verifying-key gamma points equal the delta points. "
                        "This degenerates the pairing equation and lets an attacker accept ARBITRARY "
                        "proofs (the FOOMCASH/Veil misconfiguration). Almost certainly a broken/"
                        "skipped trusted setup."
                    ),
                    impact_score=10.0, confidence_score=8.0, severity_candidate="critical",
                    evidence={"source": "zk_verifier", "bug_class": "zk_verifier_param",
                              "gamma_eq_delta": True, "unprivileged": True, "needs_poc": True},
                    next_tests=["Submit a junk proof on a fork; if it verifies, confirmed",
                                "Re-run the trusted setup; gamma and delta must differ"],
                    affected_functions=["verifyProof"],
                ))
            if all(int(v, 16 if v.startswith("0x") else 10) == 0 for v in gamma) or \
               all(int(v, 16 if v.startswith("0x") else 10) == 0 for v in delta):
                out.append(FindingCandidate(
                    detector="zk_verifier",
                    title="Groth16 verifying key: zero gamma/delta point",
                    description=("A Groth16 verifying-key gamma/delta point is all-zero — the "
                                 "pairing check is degenerate and proofs may be forgeable."),
                    impact_score=9.5, confidence_score=6.0, severity_candidate="critical",
                    evidence={"source": "zk_verifier", "bug_class": "zk_verifier_param",
                              "zero_point": True, "unprivileged": True, "needs_poc": True},
                    next_tests=["Verify the VK points came from a real, audited ceremony"],
                    affected_functions=["verifyProof"],
                ))
        return out
