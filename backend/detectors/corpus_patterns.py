"""Data-mined bug-family detector from the user-provided audit corpus.

The source archives contain tens of thousands of contest/report rows. This
detector does not try to clone every report. Instead, it converts the largest
recurring classes into conservative source-shape checks and emits lead-level
candidates for ultra-deep-v2.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies


RULES_PATH = Path(__file__).resolve().parents[1] / "data" / "corpus_pattern_rules.json"

_SWAP_NAME_RE = re.compile(
    r"swap|trade|exchange|zap|addLiquidity|removeLiquidity|mint|redeem|withdraw|deposit",
    re.I,
)
_SWAP_CALL_RE = re.compile(
    r"exactInput|exactOutput|swapExact|swapFor|swapTokens|addLiquidity|removeLiquidity|"
    r"getAmountsOut|amountOut|amountIn|router\s*\.",
    re.I,
)
_SLIPPAGE_GUARD_RE = re.compile(
    r"min(?:imum)?(?:Amount)?Out|minOut|amountOutMin|minReceived|minReturn|"
    r"slippage|maxSlippage|minShares|minAssets",
    re.I,
)
_DEADLINE_RE = re.compile(r"deadline|expiry|expire|block\.timestamp\s*[<>=]", re.I)

_CHAINLINK_RE = re.compile(r"latestRoundData\s*\(|latestAnswer\s*\(", re.I)
_ORACLE_FRESH_RE = re.compile(
    r"updatedAt|answeredInRound|roundId|heartbeat|stale|timeout|maxDelay|"
    r"block\.timestamp\s*-\s*\w+",
    re.I,
)

_FOR_LOOP_RE = re.compile(r"\bfor\s*\([^;]*;[^;]*<\s*([A-Za-z_][\w.]*)\.length", re.I)
_EXTERNAL_OR_STATE_RE = re.compile(
    r"\.call\s*[({]|\.delegatecall\s*\(|\.transfer\s*\(|safeTransfer\s*\(|"
    r"safeTransferFrom\s*\(|transferFrom\s*\(|delete\b|push\s*\(|\w+\s*(?:\[[^]]+\])?\s*[+\-*/]?=",
    re.I,
)
_LOOP_CAP_RE = re.compile(r"limit|max|count|end|cursor|offset|batch|length\s*<=", re.I)

_LOW_LEVEL_CALL_RE = re.compile(r"\.call\s*(?:\{[^}]*\})?\s*\([^;]*\)\s*;", re.I)
_CALL_SUCCESS_RE = re.compile(
    r"\(bool\s+\w+|bool\s+\w+\s*=|require\s*\([^;]*(success|ok)|"
    r"if\s*\([^;]*(success|ok)",
    re.I,
)

_SIG_RECOVER_RE = re.compile(r"ecrecover\s*\(|ECDSA\.recover\s*\(|\.recover\s*\(", re.I)
_NONCE_RE = re.compile(r"nonce|nonces|usedSignatures|executed|consumed|processed", re.I)
_DOMAIN_RE = re.compile(r"chainid|block\.chainid|DOMAIN_SEPARATOR|address\s*\(\s*this\s*\)", re.I)
_SIG_EXPIRY_RE = re.compile(r"deadline|expiry|expires|validUntil|block\.timestamp\s*<=", re.I)

_PRIV_SETTER_NAME_RE = re.compile(
    r"set(?:Owner|Admin|Guardian|Keeper|Operator|Manager|Treasury|Router|Oracle|"
    r"Verifier|Implementation|Minter)|transferOwnership|changeAdmin",
    re.I,
)
_ADDRESS_PARAM_RE = re.compile(r"\baddress\s+(?:calldata\s+|memory\s+)?([A-Za-z_]\w*)", re.I)
_ZERO_CHECK_RE = re.compile(r"address\s*\(\s*0\s*\)|!=\s*0x0|InvalidAddress|ZeroAddress", re.I)

_VALUE_MATH_NAME_RE = re.compile(
    r"price|value|amount|share|asset|rate|reward|fee|collateral|liquidat|quote",
    re.I,
)
_DIV_BEFORE_MUL_RE = re.compile(
    r"(?:uint\d*\s+)?([A-Za-z_]\w*)\s*=\s*[^;]+/\s*[^;]+;\s*"
    r"(?:uint\d*\s+)?[A-Za-z_]\w*\s*=\s*\1\s*\*",
    re.I | re.S,
)
_MULDIV_SAFE_RE = re.compile(r"mulDiv|FullMath|PRBMath|FixedPointMathLib|Math\.mulDiv", re.I)


class CorpusPatternDetector(Detector):
    name = "corpus_patterns"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        if getattr(ctx, "profile", "") != "ultra-deep-v2":
            return []
        if not ctx.source_files:
            return []

        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, params, tail, body in iter_function_bodies(source):
                if not _external(tail):
                    continue
                findings.extend(self._check_function(fname, params, tail, body, path))
        return findings

    def _check_function(
        self, fname: str, params: str, tail: str, body: str, path: str
    ) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []

        if (
            (_SWAP_NAME_RE.search(fname) or _SWAP_CALL_RE.search(body))
            and _SWAP_CALL_RE.search(body)
            and not _SLIPPAGE_GUARD_RE.search(params + "\n" + body)
        ):
            out.append(
                self._candidate(
                    "corpus_slippage_deadline",
                    fname,
                    path,
                    body,
                    title=f"Corpus pattern: swap/liquidity path lacks min-out slippage guard: {fname}",
                    desc=(
                        f"`{fname}` performs swap/liquidity-style operations, but no minOut/"
                        "slippage parameter or guard was visible. The attached corpus contains "
                        "many loss/front-run reports where users accepted attacker-skewed output."
                    ),
                    impact=7.0,
                    confidence=5.0,
                    tests=[
                        "Fork: sandwich the route and confirm received output can fall below user expectation.",
                        "Require minOut/minShares/minAssets and compare actual output before finalizing.",
                    ],
                )
            )
        if (
            (_SWAP_NAME_RE.search(fname) or _SWAP_CALL_RE.search(body))
            and _SWAP_CALL_RE.search(body)
            and not _DEADLINE_RE.search(params + "\n" + body)
        ):
            out.append(
                self._candidate(
                    "corpus_slippage_deadline",
                    fname,
                    path,
                    body,
                    title=f"Corpus pattern: swap/liquidity path has no deadline/expiry guard: {fname}",
                    desc=(
                        f"`{fname}` performs swap/liquidity-style operations, but no deadline/"
                        "expiry guard was visible. Old pending transactions can be executed after "
                        "market conditions change."
                    ),
                    impact=5.5,
                    confidence=4.5,
                    tests=[
                        "Add a deadline parameter and require block.timestamp <= deadline.",
                        "Replay a stale transaction on a fork after reserves move.",
                    ],
                )
            )

        if _CHAINLINK_RE.search(body) and not _ORACLE_FRESH_RE.search(body):
            out.append(
                self._candidate(
                    "corpus_chainlink_staleness",
                    fname,
                    path,
                    body,
                    title=f"Corpus pattern: oracle feed consumed without freshness checks: {fname}",
                    desc=(
                        f"`{fname}` reads Chainlink-style latest data but no updatedAt/"
                        "answeredInRound/heartbeat check was visible. The corpus has many stale "
                        "oracle reports where frozen feeds misprice collateral, rewards, or swaps."
                    ),
                    impact=7.0,
                    confidence=6.0,
                    tests=[
                        "Require updatedAt is recent and answeredInRound >= roundId.",
                        "Fork/mock a stale oracle response and confirm the protocol rejects it.",
                    ],
                )
            )

        if _FOR_LOOP_RE.search(body) and _EXTERNAL_OR_STATE_RE.search(body) and not _LOOP_CAP_RE.search(params + tail):
            out.append(
                self._candidate(
                    "corpus_unbounded_loop_dos",
                    fname,
                    path,
                    body,
                    title=f"Corpus pattern: externally callable unbounded loop can DoS actions: {fname}",
                    desc=(
                        f"`{fname}` loops over a dynamic array length while mutating state or "
                        "performing external/value actions, with no visible pagination or cap. "
                        "The corpus contains many gas-limit DoS reports for this shape."
                    ),
                    impact=6.5,
                    confidence=4.5,
                    tests=[
                        "Grow the array on a fork until this function exceeds the block gas limit.",
                        "Add pagination, bounded batch size, or per-item pull accounting.",
                    ],
                )
            )

        if _LOW_LEVEL_CALL_RE.search(body) and not _CALL_SUCCESS_RE.search(body):
            out.append(
                self._candidate(
                    "corpus_low_level_call_unchecked",
                    fname,
                    path,
                    body,
                    title=f"Corpus pattern: low-level call result is ignored: {fname}",
                    desc=(
                        f"`{fname}` performs a low-level call but the success flag is not visibly "
                        "checked. Corpus reports show failed calls being treated as successful "
                        "settlement, payout, or execution."
                    ),
                    impact=6.5,
                    confidence=5.0,
                    tests=[
                        "Make the callee revert and verify this function reverts too.",
                        "Capture (bool success, bytes memory data) and require success.",
                    ],
                )
            )

        if _SIG_RECOVER_RE.search(body):
            missing = []
            if not _NONCE_RE.search(body):
                missing.append("nonce/used-signature")
            if not _DOMAIN_RE.search(body):
                missing.append("chain/domain")
            if not _SIG_EXPIRY_RE.search(body):
                missing.append("deadline")
            if len(missing) >= 2:
                out.append(
                    self._candidate(
                        "corpus_signature_replay",
                        fname,
                        path,
                        body,
                        title=f"Corpus pattern: signature auth missing replay/domain controls: {fname}",
                        desc=(
                            f"`{fname}` recovers a signer, but missing controls were visible: "
                            f"{', '.join(missing)}. The corpus contains many replay/cross-domain "
                            "signature reports with this shape."
                        ),
                        impact=8.0,
                        confidence=5.5,
                        tests=[
                            "Replay the same signature twice and across chain/domain/address changes.",
                            "Bind nonce, deadline, chain id, verifying contract, action, and signer intent.",
                        ],
                    )
                )

        if _PRIV_SETTER_NAME_RE.search(fname) and _ADDRESS_PARAM_RE.search(params) and not _ZERO_CHECK_RE.search(body):
            out.append(
                self._candidate(
                    "corpus_zero_address_privileged_setter",
                    fname,
                    path,
                    body,
                    title=f"Corpus pattern: privileged address setter lacks zero-address guard: {fname}",
                    desc=(
                        f"`{fname}` sets a privileged address-like value, but no address(0) guard "
                        "was visible. Corpus examples include frozen guardians/admins, lost "
                        "ownership, and permanently disabled integrations."
                    ),
                    impact=5.5,
                    confidence=5.5,
                    tests=[
                        "Call with address(0) on a fork/unit test and verify the protocol cannot enter a stuck state.",
                        "Require new privileged addresses are non-zero and, where relevant, code-bearing.",
                    ],
                )
            )

        if (
            (_VALUE_MATH_NAME_RE.search(fname) or _VALUE_MATH_NAME_RE.search(body))
            and _DIV_BEFORE_MUL_RE.search(body)
            and not _MULDIV_SAFE_RE.search(body)
        ):
            out.append(
                self._candidate(
                    "corpus_division_before_multiplication",
                    fname,
                    path,
                    body,
                    title=f"Corpus pattern: value math divides before multiplying: {fname}",
                    desc=(
                        f"`{fname}` appears to divide an intermediate value before multiplying it "
                        "again. The corpus contains many precision-loss and rounding-direction "
                        "bugs where truncation leaks value or blocks small positions."
                    ),
                    impact=6.5,
                    confidence=4.0,
                    tests=[
                        "Fuzz small, boundary, and high-decimal inputs; compare against mulDiv/high-precision math.",
                        "Move multiplication before division or use a checked mulDiv library.",
                    ],
                )
            )

        return out

    @staticmethod
    def _candidate(
        rule_id: str,
        fname: str,
        path: str,
        body: str,
        *,
        title: str,
        desc: str,
        impact: float,
        confidence: float,
        tests: list[str],
    ) -> FindingCandidate:
        rule_meta = _rule_meta(rule_id)
        return FindingCandidate(
            detector="corpus_patterns",
            title=title,
            description=desc,
            impact_score=impact,
            confidence_score=confidence,
            severity_candidate="high" if impact >= 7 else "medium",
            evidence={
                "rule_id": rule_id,
                "function": fname,
                "file": path,
                "snippet": body[:1800],
                "bug_class": rule_id.replace("corpus_", ""),
                "lead_only": True,
                "needs_poc": True,
                "corpus_pattern": {
                    "raw_hits": rule_meta.get("raw_hits"),
                    "examples": rule_meta.get("examples", []),
                    "note": "Rule mined from user-provided audit corpus; this is a lead, not proof.",
                },
            },
            next_tests=tests,
            affected_functions=[fname],
        )


def _external(tail: str) -> bool:
    if re.search(r"\b(private|internal)\b", tail or "", re.I):
        return False
    return bool(re.search(r"\b(public|external)\b", tail or "", re.I))


@lru_cache(maxsize=1)
def _rules() -> dict:
    try:
        data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
        return data.get("rules") or {}
    except Exception:
        return {}


def _rule_meta(rule_id: str) -> dict:
    meta = _rules().get(rule_id)
    return meta if isinstance(meta, dict) else {}
