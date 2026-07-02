"""Detectors: ERC-4337 smart-account signature-binding flaws.

The engine has no 4337-semantic detector — `signature_replay` only coincidentally
matches `ecrecover` in these functions and self-suppresses. Both classes below are
gated on rare, unambiguous 4337 function markers, so FP is low.

1. PaymasterUserOpBindingDetector — `validatePaymasterUserOp` verifies a signature over
   a digest that omits `callData` (and the gas fields), so a paymaster signature is
   reusable across different calls, draining the paymaster deposit.

2. UserOpChainIdReplayDetector — `validateUserOp` RECOMPUTES its own digest
   (`keccak256(abi.encode(...))`) instead of using the EntryPoint-supplied `userOpHash`,
   without binding `block.chainid` — enabling cross-chain / cross-EntryPoint replay on
   CREATE2-mirrored accounts.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies, strip_comments

_RECOVER_RE = re.compile(r"\becrecover\s*\(|\.recover\s*\(|ECDSA\s*\.\s*(?:recover|tryRecover)")
_LOCAL_DIGEST_RE = re.compile(r"keccak256\s*\(\s*abi\.encode")
_VALUE_SEND_RE = re.compile(r"\{\s*value\s*:|depositTo\s*\(|sendValue\s*\(", re.IGNORECASE)
_SESSION_CTX_RE = re.compile(r"\.validUntil|\.validAfter|\.active\b|sessionKey|permission|\bsession\b", re.IGNORECASE)
_DECODE_RE = re.compile(r"abi\.decode", re.IGNORECASE)
_TARGET_ID_RE = re.compile(r"\b(target|selector|dest|callTarget)\b", re.IGNORECASE)
_SCOPE_CHECK_RE = re.compile(
    r"require\s*\([^;]*(target|selector|dest|callTarget)\s*==|"
    r"(allowlist|whitelist|allowedTargets?|allowedSelectors?|permitted)\s*\[|"
    r"require\s*\([^;]*value\s*<=?",
    re.IGNORECASE,
)


class PaymasterUserOpBindingDetector(Detector):
    name = "paymaster_userop_binding"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or "validatePaymasterUserOp" not in source:
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if fname != "validatePaymasterUserOp":
                    continue
                body = strip_comments(raw_body)
                if not (_RECOVER_RE.search(body) and _LOCAL_DIGEST_RE.search(body)):
                    continue
                # The signed digest must bind the call: callData (and ideally gas fields).
                if re.search(r"\bcallData\b", body):
                    continue
                out.append(FindingCandidate(
                    detector="paymaster_userop_binding",
                    title="Paymaster signature does not bind userOp.callData (reusable signature)",
                    description=(
                        "`validatePaymasterUserOp` recovers a signer from a locally-built digest that does "
                        "not include `userOp.callData` (nor the gas fields). A paymaster signature authorizing "
                        "one call can therefore be replayed to sponsor a DIFFERENT call, draining the "
                        "paymaster's EntryPoint deposit. Bind the full userOp (or use the EntryPoint-supplied "
                        "userOpHash) in the signed digest."
                    ),
                    impact_score=9.0,
                    confidence_score=6.0,  # LIKELY_CRITICAL_NEEDS_POC
                    severity_candidate="critical",
                    evidence={
                        "function": fname, "file": path, "bug_class": "paymaster_userop_binding",
                        "unprivileged": True, "needs_poc": True,
                    },
                    next_tests=[
                        "Reuse a paymaster signature with different callData on a fork; expect validation to pass",
                        "Confirm the signed digest omits callData / gas fields",
                    ],
                    affected_functions=[fname],
                ))
        return out


class UserOpChainIdReplayDetector(Detector):
    name = "userop_chainid_replay"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or "validateUserOp" not in source:
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                if fname != "validateUserOp":
                    continue
                body = strip_comments(raw_body)
                # Only the local-recompute shape is at risk; using the passed userOpHash is fine.
                if not (_LOCAL_DIGEST_RE.search(body) and _RECOVER_RE.search(body)):
                    continue
                if re.search(r"recover\s*\(\s*userOpHash", body):
                    continue
                if re.search(r"block\.chainid", body):
                    continue
                out.append(FindingCandidate(
                    detector="userop_chainid_replay",
                    title="validateUserOp recomputes its digest without chainid (cross-chain replay)",
                    description=(
                        "`validateUserOp` builds its own signing digest with `keccak256(abi.encode(...))` "
                        "instead of using the EntryPoint-supplied `userOpHash`, and the digest binds no "
                        "`block.chainid` (nor entryPoint/address(this)). On a CREATE2-mirrored account with the "
                        "same address on another chain, a signed userOp can be replayed cross-chain / "
                        "cross-EntryPoint. Sign the EntryPoint userOpHash, or include block.chainid + the "
                        "EntryPoint address in the digest."
                    ),
                    impact_score=8.0,
                    confidence_score=5.0,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={
                        "function": fname, "file": path, "bug_class": "userop_chainid_replay",
                        "needs_poc": True,
                    },
                    next_tests=[
                        "Replay a signed userOp on a mirrored account on another chain; expect it to validate",
                        "Confirm the digest omits block.chainid and does not use the passed userOpHash",
                    ],
                    affected_functions=[fname],
                ))
        return out


class ValidateUserOpMissingPrefundDetector(Detector):
    """validateUserOp receives `missingAccountFunds` but never pays it back to the
    EntryPoint (no call{value:}/depositTo/sendValue of it), so the account cannot cover
    its own prefund — griefing / stuck userOps. Tight marker gate, low FP."""
    name = "validateuserop_missing_prefund"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source or "validateUserOp" not in source:
                continue
            for fname, params, _t, raw_body in iter_function_bodies(source):
                if fname != "validateUserOp" or "missingAccountFunds" not in (params or ""):
                    continue
                body = strip_comments(raw_body)
                if _VALUE_SEND_RE.search(body):
                    continue  # it does forward the prefund
                out.append(FindingCandidate(
                    detector="validateuserop_missing_prefund",
                    title="validateUserOp never repays missingAccountFunds to the EntryPoint",
                    description=(
                        "`validateUserOp` takes a `missingAccountFunds` parameter but never sends that value "
                        "back to the EntryPoint (no `call{value: missingAccountFunds}` / `depositTo`). The "
                        "account cannot cover its own prefund, so bundlers reject its userOps (griefing / DoS). "
                        "Forward the missing funds to `msg.sender` (the EntryPoint) when it is non-zero."
                    ),
                    impact_score=5.5,
                    confidence_score=4.5,  # LOW_OR_INFO / lead
                    severity_candidate="medium",
                    evidence={
                        "function": fname, "file": path, "bug_class": "validateuserop_missing_prefund",
                        "needs_poc": True,
                    },
                    next_tests=[
                        "Submit a userOp needing a prefund on a fork; expect the bundler/EntryPoint to reject it",
                        "Confirm missingAccountFunds is never forwarded via call{value:}/depositTo",
                    ],
                    affected_functions=[fname],
                ))
        return out


class SessionKeyUnscopedDetector(Detector):
    """A session/permission validator that decodes callData into a target/selector but
    approves it WITHOUT comparing target/selector to an allowlist or value to a cap —
    session-key scope escalation (Kernel/ZeroDev/Safe/ERC-7579). Dual co-occurrence gate
    (session struct + callData decode) keeps the negative-signal FP acceptable; lead."""
    name = "session_key_unscoped"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _p, _t, raw_body in iter_function_bodies(source):
                body = strip_comments(raw_body)
                if not (_SESSION_CTX_RE.search(body) and _DECODE_RE.search(body) and _TARGET_ID_RE.search(body)):
                    continue
                if _SCOPE_CHECK_RE.search(body):
                    continue  # it does scope the target/selector/value
                out.append(FindingCandidate(
                    detector="session_key_unscoped",
                    title=f"Session-key validation does not scope the decoded target/selector: {fname}",
                    description=(
                        f"`{fname}` validates a session/permission and decodes the callData into a target/"
                        "selector but approves it without any `require(target == allowed)` / selector allowlist "
                        "/ value cap. A session key intended for one action can call ANY target — scope "
                        "escalation that drains the smart account. Enforce a per-key target+selector allowlist "
                        "and a value cap before returning valid."
                    ),
                    impact_score=7.0,
                    confidence_score=3.5,  # NEEDS_MORE_INVESTIGATION lead
                    severity_candidate="high",
                    evidence={"function": fname, "file": path, "bug_class": "session_key_unscoped", "needs_poc": True},
                    next_tests=[
                        "Use a session key to call an out-of-scope target/selector on a fork; expect it to validate",
                        "Confirm no target/selector allowlist or value cap gates the decoded call",
                    ],
                    affected_functions=[fname],
                ))
        return out
