"""Detector: comprehensive on-chain ZK / proof-verifier vulnerability analysis.

Rebuilt from the v0.4 settlement-binding stub into a 20-rule ruleset spanning the
on-chain-detectable ZK bug taxonomy. Each rule was designed *and* adversarially
false-positive-checked with a positive AND a negative Solidity fixture; those
fixtures are the accuracy suite in tests/test_zk_detector.py.

Honesty discipline (the entire point of this tool):
  * "confirmable" rules   -> the defect is fully visible in Solidity (ignored
                             verify() return, no-op verifier, nullifier not set
                             before transfer, gamma==delta VK). confidence may be
                             high.
  * "lead_only" rules     -> Solidity shows the RISK SURFACE but cannot prove
                             exploitability (the binding may legitimately live in
                             the off-chain circuit's public-input layout).
                             confidence capped <= 5, triaged NEEDS_INVESTIGATION.
  * one informational note -> the circuit itself is OUT of a Solidity tool's reach.

This is exactly why the real Aztec escapeHatch drain (17 Jun 2026, 1,158 ETH) is
surfaced as a LEAD rather than a false negative: verify() WAS called and passed,
but the released amount (caller-supplied proofId/publicOutput) was never bound to
the proof. A naive "is verify() present?" check clears it; the binding check does
not. Every value-binding rule keys on the released value, not the verify() call.
"""
from __future__ import annotations

import re

from .base import (
    Detector,
    FindingCandidate,
    TargetContext,
    header_has_access_control,
    iter_function_bodies,
    strip_comments,
)

COVERAGE_STATEMENT = (
    "Detects ZK-verifier INTEGRATION flaws visible in Solidity text (no AST, no "
    "circuit). CONFIRMS purely on-chain defects (ignored verify() return, no-op "
    "verifier, unchecked staticcall success, nullifier consumed without a "
    "spent-check or marked spent after the transfer, Groth16 VK gamma==delta / "
    "zero / placeholder points, unguarded setVerifier, caller-supplied verifier, "
    "unanchored Merkle root, missing field-range check, missing pause/liveness "
    "gate). Only LEADS (confidence <=5) on proof-to-value binding (forced-exit / "
    "escapeHatch released amount/recipient/fee, values extracted from proofData) "
    "and on settlement-boundary count binding (whether a caller-supplied tx/slot "
    "count matches the proof-committed range — the Aztec Connect numTxs class): "
    "these live partly in the circuit, so Solidity shows the risk surface but "
    "cannot prove exploitability. CANNOT detect circuit-level soundness "
    "(under-constrained signals, witness non-determinism, input packing vs "
    "circuit) — one informational note marks that. A clean scan is NOT a "
    "soundness guarantee."
)

# --------------------------------------------------------------------------- #
# ZK context gate. Broad on purpose: the rules below are what actually fire, and
# false criticals are guarded by per-rule logic + lead-only confidence caps. A
# plain ERC20/vault scores 0 here and is never touched.
# --------------------------------------------------------------------------- #
_STRONG = (
    "verifyproof", "verifyingkey", "g1point", "g2point", "groth16", "plonk",
    "snark", "pairing", "snark_scalar_field", "nullifier", "verifytx",
    "ecpairing", "escapehatch", "performdesert", "withdrawdesert", "proveexit",
)
_WEAK = (
    "verify(", ".verify", "verifier", "setverifier", "updateverifier", "proof",
    "commitment", "stateroot", "merkleroot", "publicinput", "publicsignals",
    "isknownroot", "staticcall", "executebatch", "commitbatch", "pubdata",
    "onchainoperationshash", "storedbatchhashes", "committedroot", "provebatch",
    "desert", "roothistory",
)


def _zk_score(low: str) -> tuple[int, bool]:
    score, strong = 0, False
    for t in _STRONG:
        if t in low:
            score += 2
            strong = True
    for t in _WEAK:
        if t in low:
            score += 1
    return score, strong


# --------------------------------------------------------------------------- #
# Shared regexes / helpers
# --------------------------------------------------------------------------- #
# A verify CALL name: verif + y/yProof/yTx/... (NOT bare "verifier", which has an
# 'i' after "verif").
_VERIFY_NAME = r"verif(?:y|yproof|ytx|yplonk|ygroth16|yandupdate)\w*"
_VERIFY_CALL_RE = re.compile(r"[\w.]*" + _VERIFY_NAME + r"\s*\(", re.I)

# Value-moving sinks, with an amount capture where it is the 1st/2nd positional.
_SINK_AMOUNT_RE = re.compile(
    r"\.call\s*\{\s*value\s*:\s*([\w.\[\]]+)"
    r"|\.transfer\s*\(\s*([\w.\[\]]+)\s*\)"
    r"|\.send\s*\(\s*([\w.\[\]]+)\s*\)"
    r"|_mint\s*\([^,()]+,\s*([\w.\[\]]+)\s*\)"
    r"|increaseBalanceToWithdraw\s*\(",
    re.I,
)
_VALUE_MOVE_RE = re.compile(
    r"\.call\s*\{\s*value\s*:|\.transfer\s*\(|\.send\s*\(|"
    r"safeTransfer(?:From)?\s*\(|_mint\s*\(|increaseBalanceToWithdraw\s*\(",
    re.I,
)
_HASH_CALL_RE = re.compile(r"(?:abi\.encode\w*|keccak256|sha256|poseidon)\s*\(", re.I)


def _binding_text(body: str) -> str:
    """Concatenate every place a value is 'bound to the proof' in this body:
    verify(...) argument lists, public-input array literals `[...]`, and
    hash/commitment preimages (abi.encode/keccak256/sha256/poseidon args).
    A token that appears here is considered bound to what the proof checks.
    """
    chunks: list[str] = []
    for m in re.finditer(_VERIFY_NAME + r"\s*\(([^;]*)\)", body, re.I):
        chunks.append(m.group(1))
    for m in re.finditer(r"\[([^\];]*)\]", body):  # public-input vectors only
        inner = m.group(1)
        if "," in inner or "(" in inner:  # a signal list / cast, not a bare index
            chunks.append(inner)
    for m in re.finditer(
        r"(?:abi\.encode\w*|keccak256|sha256|poseidon)\s*\(([^;]*)\)", body, re.I
    ):
        chunks.append(m.group(1))
    return " ".join(chunks).lower()


def _word(tok: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(tok) + r"\b", re.I)


def _param_names(params: str) -> list[str]:
    """Best-effort: last identifier of each comma-separated param declaration."""
    out: list[str] = []
    for part in params.split(","):
        ids = re.findall(r"[A-Za-z_]\w*", part)
        if ids:
            out.append(ids[-1])
    return out


def _released_amount(body: str) -> str | None:
    for m in _SINK_AMOUNT_RE.finditer(body):
        for g in m.groups():
            if g:
                return g
    return None


def _assigned_from_state(token: str, body: str) -> bool:
    # token = something[...]  OR  token = <statey-name>...
    if re.search(_word(token).pattern + r"\s*=\s*[\w.]*\[", body, re.I):
        return True
    return bool(
        re.search(
            _word(token).pattern
            + r"\s*=\s*[\w.]*\b(deposits?|deposited|notes?|leaves|balances?|"
            r"commitments?|stored\w*)\b",
            body,
            re.I,
        )
    )


def _require_binds(token: str, body: str) -> bool:
    for m in re.finditer(r"require\s*\(([^;]*?)\)\s*;", body, re.I):
        seg = m.group(1)
        if _word(token).search(seg) and re.search(r"(<=|>=|==)", seg):
            return True
    return False


def _has_access_control(tail: str, body: str) -> bool:
    if header_has_access_control(tail):
        return True
    return bool(
        re.search(
            r"msg\.sender\s*==\s*\w*(owner|admin|governance|timelock|guardian)",
            body,
            re.I,
        )
        or re.search(r"_check(Owner|Role)\s*\(|hasRole\s*\(|_authorize", body, re.I)
    )


# --------------------------------------------------------------------------- #
class ZkVerifierDetector(Detector):
    name = "zk_verifier"
    profiles = None

    # --------------------------------------------------------------- emit --- #
    @staticmethod
    def _mk(
        rule_id: str,
        title: str,
        desc: str,
        impact: float,
        conf: float,
        sev: str,
        tier: str,
        bug_class: str,
        fn: str | None = None,
        tests: list[str] | None = None,
        extra: dict | None = None,
    ) -> FindingCandidate:
        ev = {
            "source": "zk_verifier",
            "rule_id": rule_id,
            "bug_class": bug_class,
            "onchain_detectable": tier,
            "needs_poc": tier != "out_of_scope",
        }
        if tier == "lead_only":
            ev["lead_only"] = True
        if extra:
            ev.update(extra)
        return FindingCandidate(
            detector="zk_verifier",
            title=title,
            description=desc,
            impact_score=impact,
            confidence_score=conf,
            severity_candidate=sev,
            evidence=ev,
            next_tests=tests or [],
            affected_functions=[fn] if fn else [],
        )

    # ----------------------------------------------------------------- run -- #
    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        src = ctx.all_source_text()
        if not src:
            return []
        low = strip_comments(src).lower()
        score, strong = _zk_score(low)
        if score < 2:
            return []  # not a ZK / proof-verifying contract

        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            s = strip_comments(source)
            slow = s.lower()
            for name, params, tail, body in iter_function_bodies(s):
                findings += self._function_rules(name, params, tail, body, s, path)
            findings += self._file_rules(s, slow, path)

        if strong:
            findings.append(self._circuit_note())
        return findings

    # ---------------------------------------------------- per-function ----- #
    def _function_rules(
        self, name: str, params: str, tail: str, body: str, filesrc: str, path: str
    ) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        is_view = bool(re.search(r"\b(view|pure)\b", tail))
        binding = _binding_text(body)

        # ---- Rule 1: forced-exit / escapeHatch released value unbound ------ #
        # Only meaningful when the function actually sits in a proof-gated path:
        # "unbound to the proof" is vacuous if there is no proof here (a plain
        # time-gated escape hatch is rule 18's job, not this one).
        proof_ctx = bool(re.search(r"verif|\bproof\b|commitment|publicinput", body, re.I))
        if proof_ctx and re.search(
            r"escapehatch|escapeexit|forced?_?exit|forced?_?withdraw|"
            r"emergency(exit|withdraw)|performexit|performdesert|withdrawdesert|"
            r"proveexit|^exit$|withdraw",
            name,
            re.I,
        ) and not is_view:
            amt = _released_amount(body)
            if amt and _word(amt).search(params):  # caller-supplied amount
                bound = (
                    bool(_word(amt).search(binding))
                    or _assigned_from_state(amt, body)
                    or _require_binds(amt, body)
                )
                if not bound:
                    out.append(self._mk(
                        "forced_exit_released_value_unbound_to_proof",
                        f"Forced-exit/escapeHatch releases caller-supplied amount "
                        f"not bound to the proof: {name}",
                        f"`{name}` releases value where the amount `{amt}` is a "
                        "caller-supplied parameter that is NOT folded into the "
                        "verify() public inputs / commitment, NOR read from "
                        "proof-committed state. This is the Aztec escapeHatch "
                        "drain class: verify() may be present and pass, yet the "
                        "released amount is unconstrained by the proof.",
                        10.0, 5.0, "high", "lead_only", "proof-to-value-binding",
                        fn=name,
                        tests=[
                            "Trace the released-amount symbol to its origin (param vs proof-committed storage).",
                            "Confirm the proof public inputs commit to the withdrawn amount at the assumed index.",
                            "Fork-test: craft a valid proof but call with an inflated amount against a small/zero deposit.",
                        ],
                        extra={"released_amount": amt},
                    ))

        # ---- Rule 2: exit commitment omits / redirects recipient ----------- #
        recip = self._recipient_param(params)
        if recip and not is_view and _HASH_CALL_RE.search(body) and _VERIFY_CALL_RE.search(body):
            credits_recip = bool(
                re.search(r"\b(bal|balances?)\s*\[\s*" + re.escape(recip) + r"\s*\]", body, re.I)
                or re.search(re.escape(recip) + r"\s*\.\s*(transfer|send|call)", body, re.I)
                or re.search(r"payable\s*\(\s*" + re.escape(recip) + r"\s*\)", body, re.I)
                or re.search(r"\.call\s*\{\s*value[^}]*\}\s*\(\s*" + re.escape(recip), body, re.I)
            )
            if credits_recip and not _word(recip).search(binding):
                out.append(self._mk(
                    "exit_commitment_omits_or_redirects_recipient",
                    f"Exit/withdraw recipient not bound into the proof commitment: {name}",
                    f"`{name}` credits/transfers to caller-supplied `{recip}` which "
                    "is not part of the verified commitment / public inputs, so an "
                    "observer can front-run a valid proof and redirect the funds.",
                    8.0, 4.0, "high", "lead_only", "proof-to-value-binding",
                    fn=name,
                    tests=[
                        "Front-run a pending exit with the same proof but a different recipient.",
                        "Confirm the recipient is a constrained circuit public signal vs a free arg.",
                    ],
                    extra={"recipient": recip},
                ))

        # ---- Rule 3: withdrawal fee / relayer cut unbound / unbounded ------ #
        fee = self._named_param(params, r"\w*fee\w*|relayerfee")
        relayer = self._named_param(params, r"\w*relayer\w*")
        if fee and relayer and not is_view and re.search(
            r"-\s*" + re.escape(fee) + r"\b|" + re.escape(relayer) + r"\s*\.\s*transfer|"
            r"transfer\s*\(\s*" + re.escape(fee), body, re.I
        ):
            bounded = bool(
                re.search(r"require\s*\([^;]*\b" + re.escape(fee) + r"\b[^;]*<=?", body, re.I)
            )
            if not _word(fee).search(binding) and not bounded:
                out.append(self._mk(
                    "withdrawal_fee_relayer_unbound_or_unbounded",
                    f"Withdrawal fee/relayer cut not bound to proof and not "
                    f"bounded <= amount: {name}",
                    f"`{name}` pays a caller/relayer-supplied fee `{fee}` that is "
                    "neither a verified public input nor bounded (`require(fee <= "
                    "amount)`); a relayer can set fee == amount and take the whole "
                    "withdrawal, or the subtraction underflows.",
                    8.0, 5.0, "high", "lead_only", "proof-to-value-binding",
                    fn=name,
                    tests=[
                        "As relayer set fee == amount; confirm recipient receives zero.",
                        "Confirm fee is a circuit public input (Tornado relayer-binding) or bounded on-chain.",
                    ],
                    extra={"fee": fee, "relayer": relayer},
                ))

        # ---- Rule 4: action params absent from verify public inputs -------- #
        if _VERIFY_CALL_RE.search(body) and not is_view:
            missing = []
            for pid in _param_names(params):
                if re.fullmatch(
                    r"(recipient|to|amount|value|nullifier|root|commitment|relayer|fee)",
                    pid, re.I,
                ):
                    consumed = bool(
                        _word(pid).search(_sink_region(body))
                        or re.search(r"\[\s*" + re.escape(pid) + r"\s*\]\s*=", body, re.I)
                    )
                    if consumed and not _word(pid).search(binding):
                        missing.append(pid)
            if missing:
                out.append(self._mk(
                    "public_inputs_not_fed_to_verify",
                    f"Security-critical values absent from verify() public inputs: "
                    f"{name} ({', '.join(missing)})",
                    f"`{name}` enforces a proof but acts on {', '.join(missing)} "
                    "which is never handed to the verifier, so the proof is valid "
                    "for arbitrary values of it.",
                    9.0, 5.0, "high", "lead_only", "public-signal-not-bound",
                    fn=name,
                    tests=[
                        "For each flagged value confirm it is genuinely a circuit public input vs private/derived.",
                        "Confirm the public-input array length matches the verifier's nPublicInputs.",
                    ],
                    extra={"missing": missing},
                ))

        # ---- Rule 5: verify() return value ignored ------------------------- #
        for stmt in _statements(body):
            st = stmt.strip()
            if re.match(r"^[\w.]*" + _VERIFY_NAME + r"\s*\(.*\)$", st, re.I) and not re.match(
                r"^(require|assert|if|return|revert|while|for)\b", st
            ):
                out.append(self._mk(
                    "verify_return_value_ignored",
                    f"Verifier return value ignored (bare call): {name}",
                    f"`{name}` calls the proof verifier as a bare statement and "
                    "discards its boolean result, so any proof passes and the "
                    "contract proceeds to change state / move value.",
                    9.0, 8.0, "critical", "confirmable", "verifier-invocation-flaw",
                    fn=name,
                    tests=[
                        "Confirm value/state changes after the ignored verify().",
                        "Verify the symbol is the proof verifier, not an unrelated check.",
                    ],
                ))
                break
        else:
            mb = re.search(r"\bbool\s+(\w+)\s*=\s*[\w.]*" + _VERIFY_NAME + r"\s*\(", body, re.I)
            if mb:
                v = mb.group(1)
                used = bool(
                    re.search(r"(require|assert|if)\s*\([^;]*\b" + re.escape(v) + r"\b", body, re.I)
                    or re.search(r"(&&|\|\||!)\s*" + re.escape(v) + r"\b", body)
                    or re.search(r"\breturn\b[^;]*\b" + re.escape(v) + r"\b", body)
                    or re.search(r"\w+\s*\([^;]*\b" + re.escape(v) + r"\b[^;]*\)", body)
                )
                if not used:
                    out.append(self._mk(
                        "verify_return_value_ignored",
                        f"Verifier return value assigned but never required: {name}",
                        f"`{name}` stores the verifier result in `{v}` but never "
                        "gates on it, so an invalid proof does not stop execution.",
                        9.0, 8.0, "critical", "confirmable", "verifier-invocation-flaw",
                        fn=name,
                        tests=["Confirm the bool is not consumed in a helper before state change."],
                        extra={"unused_bool": v},
                    ))

        # ---- Rule 6: no-op / stub verifier returns true -------------------- #
        if re.search(r"verif(y|yproof|ytx)", name, re.I) and re.search(
            r"return\s+true\s*;", body, re.I
        ):
            disq = re.search(
                r"staticcall|delegatecall|\bcall\s*\(|pairing|ecpairing|ecmul|ecadd|"
                r"0x08|require\s*\(|assert\s*\(|revert|return\s+\w+\s*(&&|\|\||\.)|"
                r"return\s+(?!true)\w+\s*;",
                body, re.I,
            )
            if not disq:
                out.append(self._mk(
                    "noop_stub_verifier_returns_true",
                    f"No-op / stub verifier unconditionally returns true: {name}",
                    f"`{name}` is a placeholder verifier whose body returns true "
                    "for every input — if wired into production it accepts all "
                    "proofs and fully breaks soundness.",
                    10.0, 8.0, "critical", "confirmable", "verifier-invocation-flaw",
                    fn=name,
                    tests=[
                        "Confirm this verifier is the one wired into the production router/processor.",
                        "Distinguish a /test/ or /mock/ stub from a deployed contract.",
                    ],
                ))

        # ---- Rule 7: assembly staticcall success unchecked ----------------- #
        ms = re.search(r"(\w+)\s*:=\s*(?:staticcall|call)\s*\(", body, re.I)
        if ms and re.search(r"verif", body, re.I):
            sv = ms.group(1)
            guarded = bool(
                re.search(r"require\s*\(\s*" + re.escape(sv) + r"\b", body, re.I)
                or re.search(r"assert\s*\(\s*" + re.escape(sv) + r"\b", body, re.I)
                or re.search(r"if\s*\(\s*!\s*" + re.escape(sv) + r"\b", body, re.I)
                or re.search(r"iszero\s*\(\s*" + re.escape(sv) + r"\s*\)", body, re.I)
                or re.search(r"if\s*\(\s*" + re.escape(sv) + r"\b", body, re.I)
            )
            if not guarded:
                out.append(self._mk(
                    "verifier_staticcall_success_unchecked",
                    f"Assembly staticcall to verifier with success flag unchecked: {name}",
                    f"`{name}` assigns the verifier staticcall success flag `{sv}` "
                    "but never requires it; an invalid proof makes the verifier "
                    "revert (success=0), which is silently ignored, and state "
                    "mutation / withdrawal proceeds.",
                    9.0, 7.0, "high", "confirmable", "verifier-invocation-flaw",
                    fn=name,
                    tests=[
                        "Confirm the verifier reverts (not returns bool) on an invalid proof.",
                        "Trace that state mutation occurs after the unchecked staticcall.",
                    ],
                    extra={"success_var": sv},
                ))

        # ---- Rule 8: setVerifier without access control -------------------- #
        if re.fullmatch(r"(set|update|upgrade|change)\w*verifier\w*", name, re.I):
            assigns = re.search(r"verifier\w*\s*=", body, re.I)
            external = bool(re.search(r"\b(external|public)\b", tail)) or "unknown" in tail
            if assigns and external and not _has_access_control(tail, body):
                out.append(self._mk(
                    "set_verifier_no_access_control",
                    f"Verifier address mutable with no access control: {name}",
                    f"`{name}` reassigns the trusted proof verifier with no access "
                    "control, letting anyone point the system at a no-op verifier "
                    "that accepts every proof, then drain via the normal path.",
                    9.0, 7.0, "high", "confirmable", "mutable_verifier_trust",
                    fn=name,
                    tests=[
                        "From an unprivileged EOA call setVerifier(noOpVerifier) on a fork; confirm success.",
                        "Check whether a proxy admin / timelock guards it off-source; if so downgrade.",
                    ],
                ))

        # ---- Rule 9: verifier taken from caller-supplied parameter --------- #
        vparam = self._verifier_param(params)
        if vparam and not is_view:
            invoked = bool(
                re.search(re.escape(vparam) + r"\s*\.\s*" + _VERIFY_NAME, body, re.I)
                or re.search(r"I\w*[Vv]erifier\s*\(\s*" + re.escape(vparam) + r"\s*\)\s*\.\s*" + _VERIFY_NAME, body, re.I)
            )
            gated = bool(
                re.search(
                    r"require\s*\([^;]*" + re.escape(vparam) + r"[^;]*(==|allowed|whitelist|trusted|registry)",
                    body, re.I,
                )
                or re.search(r"(isallowed|allowedverifiers)\s*[\(\[]\s*" + re.escape(vparam), body, re.I)
            )
            if invoked and not gated:
                out.append(self._mk(
                    "verifier_from_caller_supplied_source",
                    f"Proof verifier taken from a caller-supplied parameter: {name}",
                    f"`{name}` invokes a verifier passed in as `{vparam}` rather "
                    "than an immutable/trusted address; an attacker supplies a "
                    "contract whose verify() returns true and settles a forged exit.",
                    9.0, 7.0, "critical", "confirmable", "attacker_controlled_verifier",
                    fn=name,
                    tests=[
                        "Deploy a malicious verifier returning true; call with a forged proof on a fork.",
                        "Check for an allowlist/equality guard the regex may have missed.",
                    ],
                    extra={"verifier_param": vparam},
                ))

        # ---- Rules 10/11: nullifier spent-check + CEI ---------------------- #
        if re.search(r"\bnullifier\w*\b", body, re.I) and _VALUE_MOVE_RE.search(body) and not is_view:
            spent_check = re.search(
                r"require\s*\(\s*!\s*[\w.]*(nullifier\w*|spent\w*|isspent\w*|usednullifiers?)\s*\[",
                body, re.I,
            ) or re.search(
                r"require\s*\(\s*!\s*[\w.]*(nullifier\w*|spent\w*)\s*\[",
                filesrc, re.I,
            )
            if not spent_check:
                out.append(self._mk(
                    "nullifier_no_spent_check",
                    f"Nullifier consumed without a spent-check (replay): {name}",
                    f"`{name}` moves value referencing a nullifier but never gates "
                    "on `require(!nullifierSpent[n])`; the same proof+nullifier can "
                    "be replayed to drain the pool repeatedly.",
                    9.0, 7.0, "critical", "confirmable", "nullifier_double_spend",
                    fn=name,
                    tests=[
                        "Fork-replay the same proof+nullifier twice; expect the 2nd to revert.",
                        "Confirm the spent mapping written is the one checked (no name mismatch).",
                    ],
                ))
            else:
                guard = re.search(r"nonreentrant|reentrancyguard|_status", tail + body[:200], re.I)
                move_m = _VALUE_MOVE_RE.search(body)
                write_m = re.search(
                    r"(nullifier\w*|nullifierhashes?|isspent\w*|usednullifiers?|"
                    r"spentnullifiers?|nullifierspent)\s*\[[^\]]*\]\s*=\s*(true|1)\b",
                    body, re.I,
                )
                if not guard and move_m and write_m and write_m.start() > move_m.start():
                    out.append(self._mk(
                        "nullifier_marked_after_transfer_cei",
                        f"Nullifier marked spent AFTER the external transfer (CEI): {name}",
                        f"`{name}` performs the external send before setting the "
                        "nullifier spent; a malicious recipient re-enters with the "
                        "still-unspent nullifier and withdraws multiple times.",
                        9.0, 7.0, "high", "confirmable", "nullifier_cei",
                        fn=name,
                        tests=[
                            "Deploy a re-entering receiver; confirm double payout.",
                            "Confirm nullifierSpent is set BEFORE any external interaction (strict CEI).",
                        ],
                    ))

        # ---- Rule 12: nullifier preimage omits recipient (front-run) ------- #
        mnf = re.search(
            r"nullifier\w*\s*=\s*(?:keccak256|sha256|poseidon)\s*\(([^;]*)\)", body, re.I
        )
        if mnf and recip and not is_view:
            preimage = mnf.group(1).lower()
            pays_sender = bool(re.search(r"msg\.sender\s*\.\s*(transfer|send|call)", body, re.I))
            if not _word(recip).search(preimage) and not pays_sender:
                out.append(self._mk(
                    "nullifier_not_keyed_by_asset_or_recipient",
                    f"Nullifier preimage omits the recipient (front-run replay): {name}",
                    f"`{name}` derives the nullifier on-chain without binding "
                    f"`{recip}`, so a front-runner can replay the proof with their "
                    "own recipient and steal the withdrawal.",
                    8.0, 4.0, "high", "lead_only", "nullifier_binding",
                    fn=name,
                    tests=[
                        "Front-run a pending withdraw with the same proof but attacker recipient.",
                        "Confirm recipient is a circuit public input, not just a plaintext arg.",
                    ],
                    extra={"recipient": recip},
                ))

        # ---- Rule 15: executeBatch pubdata hash not compared --------------- #
        if re.search(
            r"executebatch|executebatches|_executeonebatch|finalize|"
            r"processwithdraw|executewithdraw",
            name, re.I,
        ) and not is_view:
            uses_pubdata = re.search(r"onchainoperationspubdata|_pubdata|\bpubdata\b", body, re.I)
            credits = re.search(
                r"increasebalancetowithdraw\s*\(|safetransfer|_mint\s*\(|"
                r"\.call\s*\{\s*value|\bbal\w*\s*\[[^\]]+\]\s*\+=",
                body, re.I,
            )
            if uses_pubdata and credits:
                compared = re.search(
                    r"(onchainoperationshash|operationshash|pubdatahash|commitment|"
                    r"priorityoperationshash)", body, re.I,
                ) and re.search(r"(!=|==|revert|require)", body)
                if not compared:
                    out.append(self._mk(
                        "execute_batch_pubdata_hash_not_compared",
                        f"executeBatch credits caller pubdata without comparing the "
                        f"recomputed hash to the proof-committed operations hash: {name}",
                        f"`{name}` reads withdrawal amounts/recipients from "
                        "caller-supplied pubdata and credits them, but never "
                        "recomputes keccak(pubdata) and reverts unless it equals "
                        "the batch's proof-verified operations hash — letting an "
                        "attacker mint arbitrary withdrawals against a valid batch.",
                        10.0, 7.0, "critical", "confirmable", "proof-to-value-binding",
                        fn=name,
                        tests=[
                            "Submit a real verified batch but execute with tampered pubData; expect revert.",
                            "Confirm the compared hash is itself bound into the proof-verified commitment.",
                        ],
                    ))

        # ---- Rule 18A: escape hatch missing liveness gate ------------------ #
        if re.search(
            r"escapehatch|forced?exit|forceexit|emergency\w*|performdesert|\bdesert\b",
            name, re.I,
        ) and _VALUE_MOVE_RE.search(body) and not is_view:
            gate = re.search(
                r"block\.(timestamp|number)|frozen|halted|paused|iscensored|"
                r"exodusmode|desertmode|lastblock\w*|\bdelay\b|\bwindow\b",
                tail + body, re.I,
            )
            if not gate and not _has_access_control(tail, body):
                out.append(self._mk(
                    "escape_hatch_missing_liveness_or_pause_gate",
                    f"Forced-exit/escape hatch has no liveness/time-window gate: {name}",
                    f"`{name}` releases value with no liveness precondition "
                    "(timestamp window, frozen/exodus flag) and no access control, "
                    "so the escape hatch is permanently open and need not wait for "
                    "a censorship/halt condition.",
                    6.0, 6.0, "medium", "confirmable", "missing_circuit_breaker",
                    fn=name,
                    tests=[
                        "Confirm the hatch should open only on censorship/halt; add the missing precondition.",
                        "Check whether settlement can be paused to stop an in-progress drain.",
                    ],
                ))

        # ---- Rule 19: packing truncation mismatch -------------------------- #
        mt = re.search(r"(uint128|uint96|uint64)\s*\(\s*(\w+)\s*\)", binding)
        if mt and not is_view:
            tv = mt.group(2)
            full_sink = re.search(
                r"\.transfer\s*\(\s*" + re.escape(tv) + r"\b|"
                r"\.call\s*\{\s*value\s*:\s*" + re.escape(tv) + r"\b|"
                r"_mint\s*\([^,]+,\s*" + re.escape(tv) + r"\b",
                body, re.I,
            )
            if full_sink:
                out.append(self._mk(
                    "public_input_packing_truncation_mismatch",
                    f"Amount narrowed in the commitment but released at full width: {name}",
                    f"`{name}` packs `{tv}` with a narrowing cast into the "
                    "commitment/public input while transferring it at full width; "
                    "if the circuit constrains a different width the binding "
                    "diverges, enabling a forged/malleable amount.",
                    5.0, 4.0, "medium", "lead_only", "public-input-packing",
                    fn=name,
                    tests=[
                        "Recover the circuit's signal width for the amount and compare to the cast.",
                        "Test amounts above the truncation width for commitment wrap vs full payout.",
                    ],
                    extra={"truncated": tv},
                ))

        # ---- Rule 21: settlement count not bound to proof (numTxs class) ---- #
        # The Aztec Connect $2.19M bug: numTxs (decoded from calldata, no
        # constraint) bounds the L1 settlement loop while the proof commits a
        # larger fixed range -> proof-committed gap slots go unvalidated on L1.
        settle_ctx = bool(
            re.search(
                r"processrollup|processblock|processbatch|executebatch|"
                r"processrollupproof|decodeproof|settle|processdeposit",
                name, re.I,
            )
            or re.search(r"publicinputshash|sha256\s*\(|verif", body, re.I)
        )
        if settle_ctx and not is_view:
            mcount = re.search(
                r"\b(num(?:real)?(?:txs|transactions|blocks)|numtxs|numrealtxs|"
                r"rollupsize|numinnerrollups|batchsize|numblocks)\b",
                body, re.I,
            )
            if mcount:
                cnt = mcount.group(1)
                bounds_proc = bool(
                    re.search(re.escape(cnt) + r"\s*[/*]", body, re.I)
                    or re.search(r"(?:div|mul)\s*\(\s*" + re.escape(cnt), body, re.I)
                    or re.search(r"<\s*[\w.]*" + re.escape(cnt) + r"\b", body, re.I)
                    or re.search(re.escape(cnt) + r"\s*[<>]", body, re.I)
                )
                bound_to_proof = bool(
                    re.search(
                        r"require\s*\(\s*[\w.]*" + re.escape(cnt) + r"\s*(==|<=)", body, re.I
                    )
                    or _word(cnt).search(_binding_text(body))
                )
                if bounds_proc and not bound_to_proof:
                    out.append(self._mk(
                        "settlement_count_not_bound_to_proof",
                        f"Settlement bounded by a caller-supplied count not bound to "
                        f"the proof: {name} ({cnt})",
                        f"`{name}` uses `{cnt}` (decoded from caller calldata) to "
                        f"bound settlement processing, but no require ties `{cnt}` "
                        "to the number of transactions/slots the ZK proof commits "
                        "to. This is the Aztec Connect settlement-boundary class: "
                        "the proof commits a fixed range while L1 processes only the "
                        "first slots, leaving proof-committed gap slots unvalidated "
                        "on L1 (unbacked balances that can be withdrawn).",
                        9.0, 4.0, "high", "lead_only", "settlement_boundary_mismatch",
                        fn=name,
                        tests=[
                            f"Confirm `{cnt}` is constrained to equal the proof-committed slot count.",
                            "Check whether gap slots beyond the processed range are forced to zero by the circuit.",
                            f"Fork-test: submit a rollup with a low `{cnt}` but real txs in the gap slots.",
                        ],
                        extra={"count_var": cnt},
                    ))

        # ---- Rule 22: value extracted from proofData, no in-fn hash-bind --- #
        # The Aztec escapeHatch/transferFee class: a value is read straight out of
        # caller proofData (extractTotalTxFee/abi.decode) and released, with no
        # recompute-and-compare of that data against the proof-committed hash here.
        if not is_view and _VALUE_MOVE_RE.search(body):
            mex = re.search(
                r"\b(\w+)\s*=\s*(?:extract\w*|_?decode\w*|abi\.decode)\s*\("
                r"[^;]*\b(?:proofdata|pubdata|calldata|proof)\b",
                body, re.I,
            )
            if mex:
                ev_amt = mex.group(1)
                flows = bool(
                    re.search(r"\.transfer\s*\([^;]*\b" + re.escape(ev_amt) + r"\b", body, re.I)
                    or re.search(r"\.call\s*\{\s*value\s*:\s*" + re.escape(ev_amt) + r"\b", body, re.I)
                    or re.search(r"_?(?:mint|transfer|credit)\w*\s*\([^;]*\b" + re.escape(ev_amt) + r"\b", body, re.I)
                    or re.search(r"safetransfer\w*\s*\([^;]*\b" + re.escape(ev_amt) + r"\b", body, re.I)
                )
                hash_bound = bool(
                    re.search(r"(keccak256|sha256)\s*\([^;]*\)\s*(==|!=)", body, re.I)
                    or re.search(r"(==|!=)\s*[\w.]*(publicinputshash|commitment|operationshash)", body, re.I)
                )
                if flows and not hash_bound:
                    out.append(self._mk(
                        "value_extracted_from_proofdata_unbound",
                        f"Value extracted from proofData and released with no "
                        f"in-function hash-binding: {name} ({ev_amt})",
                        f"`{name}` reads `{ev_amt}` directly out of caller-supplied "
                        "proofData and moves value with it, with no recompute-and-"
                        "compare of a hash of that data against the proof-committed / "
                        "public-inputs hash in this function. If the extracted offset "
                        "lies outside the proof-signed region, the value is unbound "
                        "(the Aztec transferFee/extractTotalTxFee class).",
                        9.0, 4.0, "high", "lead_only", "proof-to-value-binding",
                        fn=name,
                        tests=[
                            f"Confirm the offset `{ev_amt}` is read from lies within the proof-committed/signed region.",
                            "Trace whether a sibling function binds this data via sha256/keccak to publicInputsHash.",
                            f"Fork-test: inflate `{ev_amt}` beyond the signed region and check payout.",
                        ],
                        extra={"extracted_value": ev_amt},
                    ))

        return out

    # ----------------------------------------------------- file-level ------ #
    def _file_rules(self, s: str, slow: str, path: str) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []

        # ---- Rule 13: unanchored Merkle/state root ------------------------- #
        for name, params, tail, body in iter_function_bodies(s):
            if re.search(r"\b(bytes32|uint256)\s+\w*root\b", params, re.I) and re.search(
                r"\broot\b", body, re.I
            ) and re.search(r"verif|publicinput|\bproof\b", body, re.I):
                anchored = re.search(
                    r"isknownroot|knownroots?|_isknownroot|isvalidroot|roots\s*\[|"
                    r"roothistory|recentroots|root_history_size|"
                    r"require\s*\([^;]*root[^;]*(known|currentroot)",
                    slow,
                )
                stores_root = re.search(r"\w*root\w*\s*=\s*\w*newroot", body, re.I)
                if not anchored and not stores_root:
                    out.append(self._mk(
                        "unanchored_merkle_root_in_verification",
                        f"Caller-supplied Merkle/state root used without a "
                        f"known-root check: {name}",
                        f"`{name}` consumes a caller-supplied root in verification "
                        "without `require(isKnownRoot(root))` or a roots-history "
                        "check, letting an attacker submit a root for a tree they "
                        "control and forge membership of arbitrary commitments.",
                        9.0, 6.0, "high", "confirmable", "merkle_root_anchoring",
                        fn=name,
                        tests=[
                            "Confirm the root param is reachable by an unprivileged caller.",
                            "Confirm no inherited base supplies the root-history check.",
                        ],
                    ))
                    break  # one per file is enough

        # ---- Rule 14: commit/prove decoupling ------------------------------ #
        if re.search(r"commitbatch|commitblock", slow) and re.search(
            r"executebatch|executewithdraw|_executeonebatch|finalize|withdraw", slow
        ):
            proven_gate = re.search(
                r"provebatch|verifybatch|verifiedbatches|isproven|proof_verified|"
                r"require\s*\([^;]*proof", slow,
            )
            sink = _VALUE_MOVE_RE.search(s)
            if not proven_gate and sink:
                out.append(self._mk(
                    "commit_prove_decoupling_unproven_root",
                    "Execution anchors to an operator-committed root with no "
                    "proof-verified gate (commit/prove decoupling)",
                    "A commitBatch path stores a state root and an "
                    "execute/withdraw path anchors to it, but no proof-verified "
                    "flag ties execution to verification — an operator can post a "
                    "fraudulent root and drain before (or without) a proof.",
                    9.0, 5.0, "high", "lead_only", "merkle_root_anchoring",
                    tests=[
                        "Confirm execute/withdraw cannot run against a committed-but-unproven root.",
                        "Fork-test: commit a fraudulent root and attempt a withdraw before proveBatch.",
                    ],
                ))

        # ---- Rule 16: missing public-input field-range check --------------- #
        has_field = re.search(
            r"21888242871839275222246405745257275088548364400416034343698204186575808495617"
            r"|snark_scalar_field|prime_r|field_size",
            slow,
        )
        if has_field and re.search(_VERIFY_NAME + r"\s*\([^)]*\buint256\s*\[", s, re.I):
            checked = re.search(
                r"<\s*(snark_scalar_field|prime_r|field_size)\b|"
                r"require\s*\([^;]*input[^;]*<", slow,
            )
            if not checked:
                out.append(self._mk(
                    "public_input_missing_field_range_check",
                    "Public inputs not range-checked against the SNARK scalar "
                    "field before verify (overflow / malleability)",
                    "A hand-rolled bn254 verifier accepts a public-input array but "
                    "never requires each signal < field modulus r; an attacker can "
                    "submit p+x congruent values, enabling malleability / "
                    "double-spend on verifiers that reduce mod r and key nullifiers "
                    "on the raw input.",
                    6.0, 7.0, "medium", "confirmable", "field-overflow-malleability",
                    tests=[
                        "Confirm the verifier does not internally reduce inputs mod r.",
                        "Check the nullifier set is keyed on the raw (unreduced) input.",
                    ],
                ))

        # ---- Rule 17: Groth16 VK degenerate points ------------------------- #
        out += self._groth16_vk(s)

        return out

    # ----------------------------------------------------- helpers --------- #
    @staticmethod
    def _recipient_param(params: str) -> str | None:
        m = re.search(
            r"address\s+(?:payable\s+)?(\w*(?:recipient|receiver|dest)\w*|to|owner|l1address)\b",
            params, re.I,
        )
        return m.group(1) if m else None

    @staticmethod
    def _verifier_param(params: str) -> str | None:
        m = re.search(
            r"\b(?:address|I\w*[Vv]erifier)\s+(\w*verifier\w*)\b", params, re.I
        )
        return m.group(1) if m else None

    @staticmethod
    def _named_param(params: str, name_re: str) -> str | None:
        m = re.search(r"\b\w+\s+(?:payable\s+)?(" + name_re + r")\b", params, re.I)
        return m.group(1) if m else None

    def _groth16_vk(self, src: str) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        gamma_eq_delta = False

        # (a) G2Point coordinate-tuple form: gamma2 = G2Point(...); delta2 = G2Point(...)
        pts: dict[str, list[str]] = {"gamma": [], "delta": []}
        for m in re.finditer(
            r"(gamma|delta)\w*\s*=\s*(?:Pairing\.)?G2Point\s*\((.*)\)\s*;", src, re.I
        ):
            base = m.group(1).lower()
            norm = re.sub(r"[\s\[\]()]|uint\d*|uint", "", m.group(2)).lower()
            pts[base].append(norm)
        if pts["gamma"] and pts["delta"] and set(pts["gamma"]) & set(pts["delta"]):
            gamma_eq_delta = True

        # (b) Scalar-constant form: gammax1 = 0x..; deltax1 = 0x.. (snarkjs verifier)
        if not gamma_eq_delta:
            gd: dict[str, list[str]] = {"gamma": [], "delta": []}
            for m in re.finditer(
                r"\b(gamma|delta)[a-z0-9_]*\s*=\s*(0x[0-9a-fA-F]+|\d{6,})", src, re.I
            ):
                gd[m.group(1).lower()].append(m.group(2).lower())
            if len(gd["gamma"]) >= 2 and gd["gamma"] == gd["delta"]:
                gamma_eq_delta = True

        if gamma_eq_delta:
            out.append(self._mk(
                "groth16_vk_degenerate_points",
                "Groth16 verifying key: gamma == delta (arbitrary proof acceptance)",
                "The hardcoded Groth16 verifying-key gamma points equal the delta "
                "points. This degenerates the pairing equation and lets an attacker "
                "get ARBITRARY proofs accepted (the FOOMCASH/Veil misconfiguration) "
                "— almost certainly a broken/skipped trusted setup.",
                10.0, 8.0, "critical", "confirmable", "groth16_vk_misconfiguration",
                fn="verifyingKey",
                tests=[
                    "Confirm the gamma and delta VK tuples are byte-identical after normalization.",
                    "Submit a junk proof on a fork; if it verifies, confirmed.",
                ],
            ))
        # zero / generator-placeholder VK point
        for m in re.finditer(
            r"\b(alpha|beta|gamma|delta|vk\.\w+|ic\[\d+\])\w*\s*=\s*(?:Pairing\.)?"
            r"G[12]Point\s*\((.*)\)\s*;",
            src, re.I,
        ):
            coords = re.findall(r"0x0+\b|(?<!\w)0(?!x)\b", m.group(2))
            allcoords = re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", m.group(2))
            if allcoords and all(int(c, 16 if c.lower().startswith("0x") else 10) == 0 for c in allcoords):
                out.append(self._mk(
                    "groth16_vk_degenerate_points",
                    f"Groth16 verifying key: zero point on {m.group(1)}",
                    "A Groth16 verifying-key point is all-zero — the pairing check "
                    "is degenerate and proofs may be forgeable.",
                    9.5, 6.0, "critical", "confirmable", "groth16_vk_misconfiguration",
                    fn="verifyingKey",
                    tests=["Verify the VK points came from a real, audited ceremony."],
                ))
                break
        return out

    # ----------------------------------------------------- the note -------- #
    def _circuit_note(self) -> FindingCandidate:
        return self._mk(
            "circuit_soundness_out_of_scope_note",
            "ZK architecture detected — off-chain circuit is OUT of tool scope",
            "This contract verifies zk proofs. The deepest soundness surface "
            "(under-constrained signals, missing range constraints, witness "
            "non-determinism, recursion/aggregation layout, input packing vs the "
            "circuit) lives in the OFF-CHAIN circuit/VK and cannot be assessed by "
            "a Solidity-only tool — engage a ZK specialist with the byte-matched "
            "circuit source. Only the on-chain integration was checked here; a "
            "clean scan is NOT a soundness guarantee.",
            2.0, 9.0, "info", "out_of_scope", "circuit-soundness-out-of-scope",
            tests=["Engage a ZK auditor with the circuit repo @ the deployed commit"],
            extra={"informational": True, "out_of_tool_scope": "off-chain ZK circuit"},
        )


# --------------------------------------------------------------------------- #
def _statements(body: str) -> list[str]:
    inner = body[body.find("{") + 1 : body.rfind("}")]
    return [seg for seg in inner.split(";")]


def _sink_region(body: str) -> str:
    """Text from the first value-move/mapping-write onward — where action params
    are 'consumed'. Falls back to the whole body."""
    m = _VALUE_MOVE_RE.search(body)
    return body[m.start():] if m else body
