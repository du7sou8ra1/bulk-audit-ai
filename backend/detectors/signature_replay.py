"""Detector: signature verification / replay bypass (v0.4).

Maps to GnosisPay (Delay-module signature flaw) and Drift (signature path). Shapes:

  * `ecrecover` / `recover` used to authorize an action with NO nonce and NO
    deadline in the signed payload -> replayable signature.
  * EIP-712 verification with no domain separator / chainid -> cross-context replay.
  * `ecrecover` result used without a `== signer` / `!= address(0)` check.

This is distinct from `permit_misuse` (which targets ERC-2612 permit specifically).
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies

_SIG_RE = re.compile(r"\becrecover\s*\(|\.recover\s*\(|isValidSignature\s*\(", re.IGNORECASE)
_NONCE_RE = re.compile(r"nonce|usedSignatures?|signatureUsed|_used\[|replay", re.IGNORECASE)
_DEADLINE_RE = re.compile(r"deadline|expir|validUntil|block\.timestamp", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"DOMAIN_SEPARATOR|_domainSeparator|EIP712|chainid|block\.chainid", re.IGNORECASE)
_SIGNER_CHECK_RE = re.compile(r"==\s*\w*[Ss]igner|signer\s*==|!=\s*address\(0\)|require\([^)]*recover", re.IGNORECASE)


class SignatureReplayDetector(Detector):
    name = "signature_replay"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        text = ctx.all_source_text()
        if not text or not _SIG_RE.search(text):
            return []
        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, _tail, body in iter_function_bodies(source):
                if not _SIG_RE.search(body):
                    continue
                has_nonce = bool(_NONCE_RE.search(body))
                has_deadline = bool(_DEADLINE_RE.search(body))
                has_domain = bool(_DOMAIN_RE.search(body) or _DOMAIN_RE.search(text))
                has_signer_check = bool(_SIGNER_CHECK_RE.search(body))

                if not has_nonce and not has_deadline:
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Signature authorization with no nonce/deadline (replayable): {fname}",
                        desc=(f"`{fname}` verifies a signature (ecrecover/recover) to authorize an "
                              "action but no nonce and no deadline were found in the body. The "
                              "signature can be replayed (GnosisPay Delay-module class)."),
                        impact=8.5, conf=4.5, bug="signature",
                        tests=["Replay the same signed message twice on a fork; expect the 2nd to revert",
                               "Confirm the signed digest includes an incrementing nonce + deadline"]))
                elif not has_domain:
                    findings.append(self._c(
                        fname, path, body,
                        title=f"Signature verification without domain/chainid binding: {fname}",
                        desc=(f"`{fname}` verifies a signature but no EIP-712 domain separator / "
                              "chainid binding was found — the signature may be replayable across "
                              "chains or contracts."),
                        impact=6.5, conf=4.0, bug="signature",
                        tests=["Confirm the digest binds DOMAIN_SEPARATOR (name, version, chainid, this)"]))
                if not has_signer_check:
                    findings.append(self._c(
                        fname, path, body,
                        title=f"ecrecover result possibly used without signer/zero check: {fname}",
                        desc=(f"`{fname}` calls ecrecover/recover but no explicit `== expectedSigner` "
                              "or `!= address(0)` guard was detected. A malformed signature can "
                              "recover address(0) and bypass the check."),
                        impact=7.0, conf=3.5, bug="signature",
                        tests=["Confirm the recovered address is checked != 0 and == the expected signer"]))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, bug, tests):
        return FindingCandidate(
            detector="signature_replay", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="critical" if impact >= 9 else "high",
            evidence={"function": fname, "file": path, "snippet": body[:1500],
                      "bug_class": bug, "needs_poc": True, "unprivileged": True},
            next_tests=tests, affected_functions=[fname],
        )
