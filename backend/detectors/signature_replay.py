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
# SIG-ECRECOVER-GUARD: a RAW ecrecover (not the OZ ECDSA/SignatureChecker wrapper,
# which revert on a zero/malleable signature by construction) whose result is used
# with no `!= address(0)` guard lets a malformed signature recover address(0).
_RAW_ECRECOVER_RE = re.compile(r"\becrecover\s*\(", re.IGNORECASE)
_OZ_SIG_RE = re.compile(r"ECDSA\s*\.\s*(recover|tryRecover)\s*\(|SignatureChecker", re.IGNORECASE)
_ZERO_CHECK_RE = re.compile(r"address\s*\(\s*0\s*\)|address\s*\(\s*0x0+\s*\)", re.IGNORECASE)


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
                # Precise raw-ecrecover zero-address guard (no OZ-ECDSA false positive)
                if _RAW_ECRECOVER_RE.search(body) and not _ZERO_CHECK_RE.search(body) \
                        and not _OZ_SIG_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, tier="confirmable", rule_id="ecrecover_no_zero_check",
                        title=f"Raw ecrecover used without a zero-address guard: {fname}",
                        desc=(f"`{fname}` uses raw `ecrecover` and no `!= address(0)` / "
                              "`== address(0)`-revert guard was found. A malformed signature makes "
                              "ecrecover return address(0); if address(0) maps to a privileged/"
                              "default value the check is bypassed. (OZ `ECDSA.recover` reverts by "
                              "construction — use it, or add the zero check + an s-range malleability "
                              "check.)"),
                        impact=8.0, conf=7.0, bug="signature",
                        tests=["Submit a malformed signature so ecrecover returns address(0); check the path it unlocks",
                               "Confirm require(recovered != address(0)) AND == expected signer"]))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, bug, tests, tier=None, rule_id=None):
        ev = {"function": fname, "file": path, "snippet": body[:1500],
              "bug_class": bug, "needs_poc": True, "unprivileged": True}
        if tier:
            ev["onchain_detectable"] = tier
        if rule_id:
            ev["rule_id"] = rule_id
        return FindingCandidate(
            detector="signature_replay", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="critical" if impact >= 9 else "high",
            evidence=ev, next_tests=tests, affected_functions=[fname],
        )
