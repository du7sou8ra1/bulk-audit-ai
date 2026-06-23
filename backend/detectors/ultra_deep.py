"""Ultra-deep-only detectors (2024-2026 classes from the GitHub-research pass).

Registered ONLY in registry.ULTRA_EXTRA_DETECTORS, so they run under the
'ultra-deep' profile and NEVER under 'deep' (the frozen baseline). Each maps to a
real recent incident; see IDEAS.md for sources.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies


def _param_names(params: str) -> set[str]:
    out: set[str] = set()
    for chunk in (params or "").split(","):
        toks = chunk.replace("memory", " ").replace("calldata", " ").replace("storage", " ").split()
        if toks:
            out.add(toks[-1].strip("[]"))
    return out


# --------------------------------------------------------------------------- #
# ecrecover -> address(0) auth bypass (LegendaryMoneyMon, classic)
# --------------------------------------------------------------------------- #
_ECRECOVER_RE = re.compile(r"\becrecover\s*\(", re.I)
_ECDSA_RE = re.compile(r"ECDSA\s*\.\s*(recover|tryRecover)", re.I)
_ECREC_ZERO_GUARD_RE = re.compile(
    r"!=\s*address\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)\s*!=|"
    r"==\s*address\s*\(\s*0\s*\)|require\s*\([^;)]*\b\w+\b\s*!=\s*0\b",
    re.I,
)
_ECREC_AUTH_RE = re.compile(
    r"ecrecover\s*\([^;]*\)\s*==|==\s*ecrecover|require\s*\([^;]*ecrecover|=\s*ecrecover",
    re.I,
)


class EcrecoverZeroDetector(Detector):
    name = "ecrecover_zero"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not _ECRECOVER_RE.search(body) or _ECDSA_RE.search(body):
                    continue
                if _ECREC_ZERO_GUARD_RE.search(body) or not _ECREC_AUTH_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector=self.name,
                    title=f"ecrecover used for auth with no address(0) check: {fname}",
                    description=(
                        f"`{fname}` authorizes via ecrecover without requiring the recovered "
                        "signer != address(0). A malformed/empty signature recovers to "
                        "address(0); if the expected signer (or a default-zero authority) is "
                        "also zero, a garbage signature passes. Use OpenZeppelin ECDSA.recover "
                        "(reverts on zero) or add require(signer != address(0))."
                    ),
                    impact_score=8.5, confidence_score=7.0, severity_candidate="high",
                    evidence={"function": fname, "file": path, "snippet": body[:1500],
                              "bug_class": "signature", "needs_poc": True, "unprivileged": True},
                    next_tests=[
                        "Submit a malformed/empty signature; confirm it recovers to address(0) and passes auth",
                        "Confirm the expected signer can be address(0) (unset/default mapping)",
                    ],
                    affected_functions=[fname]))
        return out


# --------------------------------------------------------------------------- #
# EIP-1271 isValidSignature magic-value spoof (GnosisPay)
# --------------------------------------------------------------------------- #
_1271_RE = re.compile(r"isValidSignature\s*\(", re.I)
_MAGIC_RE = re.compile(r"0x1626ba7e|0x20c13b0b", re.I)
_SIGNER_OK_RE = re.compile(
    r"isOwner\s*\[|owners\s*\[|isSigner\s*\[|_?signers?\s*\[|trustedSigner|allowlist|"
    r"whitelist|==\s*(?:owner|admin|trustedSigner|expectedSigner)\b|hasRole\s*\(",
    re.I,
)


class Eip1271SpoofDetector(Detector):
    name = "eip1271_spoof"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not (_1271_RE.search(body) and _MAGIC_RE.search(body)):
                    continue
                if _SIGNER_OK_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector=self.name,
                    title=f"EIP-1271 signature accepted without authorizing the signer: {fname}",
                    description=(
                        f"`{fname}` treats an isValidSignature() magic-value return (0x1626ba7e) "
                        "as authorization, but the queried signer address is caller-controlled and "
                        "is not checked against an owner/allowlist. An attacker deploys a contract "
                        "that returns the magic value unconditionally and forges approval "
                        "(GnosisPay class). Also ensure the low-level call success flag is checked."
                    ),
                    impact_score=8.0, confidence_score=6.0, severity_candidate="high",
                    evidence={"function": fname, "file": path, "snippet": body[:1500],
                              "bug_class": "signature", "needs_poc": True, "unprivileged": True},
                    next_tests=[
                        "Deploy an IERC1271 returning 0x1626ba7e for any input; pass it as the signer; confirm forged auth",
                        "Confirm the signer is bound to an owner/allowlist, not a caller-supplied address",
                    ],
                    affected_functions=[fname]))
        return out


# --------------------------------------------------------------------------- #
# Arbitrary-`from` transferFrom (LI.FI, router approval abuse)
# --------------------------------------------------------------------------- #
_TF_RE = re.compile(r"(?:safeTransferFrom|transferFrom)\s*\(\s*([A-Za-z_]\w*)\s*,", re.I)


class ArbitraryFromTransferFromDetector(Detector):
    name = "arbitrary_from_transferfrom"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not re.search(r"\b(public|external)\b", tail):
                    continue
                pnames = _param_names(params)
                for m in _TF_RE.finditer(body):
                    frm = m.group(1)
                    if frm in pnames and frm.lower() not in ("msg", "sender", "_msgsender"):
                        out.append(FindingCandidate(
                            detector=self.name,
                            title=f"transferFrom pulls from a caller-supplied address: {fname}",
                            description=(
                                f"`{fname}` calls transferFrom with from = `{frm}`, a function "
                                "parameter rather than msg.sender. If this contract holds standing "
                                "approvals (router/aggregator), an attacker passes a victim's address "
                                "to redeem the victim's allowance (LI.FI / arbitrary-from class). "
                                "Require from == msg.sender, or validate against an allowlist."
                            ),
                            impact_score=8.5, confidence_score=6.0, severity_candidate="high",
                            evidence={"function": fname, "file": path, "snippet": body[:1500],
                                      "bug_class": "access_control", "needs_poc": True,
                                      "unprivileged": True, "from_param": frm},
                            next_tests=[
                                "Victim approves this contract; from another EOA call with from=victim; confirm tokens pulled",
                                "Confirm there is no require(from == msg.sender) or source allowlist",
                            ],
                            affected_functions=[fname]))
                        break
        return out
