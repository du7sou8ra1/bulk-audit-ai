"""Ultra-deep v2 detectors for 2026 exploit variants.

These rules are intentionally profile-isolated. They encode high-signal
structural probes from the 2026 incident corpus that were not covered well by
the first ultra-deep wave: settlement/proof boundary drift, bridge retry domain
binding, unit mismatches, zero-value transferFrom gates, component-share
accounting, single-verifier bridge configs, and allowance-drain routers.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies


def _param_names(params: str) -> set[str]:
    names: set[str] = set()
    for part in (params or "").split(","):
        toks = re.findall(r"[A-Za-z_]\w*", part)
        if toks:
            names.add(toks[-1])
    return names


def _array_params(params: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(
        r"(?:[A-Za-z_]\w*(?:\d+)?|bytes|string)\s*\[\s*\]\s*"
        r"(?:calldata|memory|storage)?\s*([A-Za-z_]\w*)",
        params,
        re.I,
    ):
        names.add(m.group(1))
    return names


def _finding(
    detector: str,
    rule_id: str,
    title: str,
    desc: str,
    impact: float,
    conf: float,
    sev: str,
    bug_class: str,
    fn: str,
    *,
    lead_only: bool = True,
    tests: list[str] | None = None,
    extra: dict | None = None,
) -> FindingCandidate:
    ev = {
        "source": detector,
        "rule_id": rule_id,
        "bug_class": bug_class,
        "needs_poc": True,
        "onchain_detectable": "lead_only" if lead_only else "confirmable",
    }
    if lead_only:
        ev["lead_only"] = True
    if extra:
        ev.update(extra)
    return FindingCandidate(
        detector=detector,
        title=title,
        description=desc,
        impact_score=impact,
        confidence_score=conf,
        severity_candidate=sev,
        evidence=ev,
        next_tests=tests or [],
        affected_functions=[fn] if fn else [],
    )


# --------------------------------------------------------------------------- #
# Aztec Connect class: proof set != settlement set
# --------------------------------------------------------------------------- #
_PROOF_SURFACE = re.compile(
    r"verifyProof|verifier\s*\.\s*verify|Groth16|Plonk|SNARK|proofData|publicInputs?",
    re.I,
)
_COUNT_NAME = re.compile(r"(num|n|count|real|tx|op|item|batch|limit|len)", re.I)
_SETTLE_SINK = re.compile(
    r"_settle|settle|finali[sz]e|withdraw|deposit|process|execute|mint|unlock|credit",
    re.I,
)


class SettlementBoundaryMismatchDetector(Detector):
    name = "settlement_boundary_mismatch"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not _PROOF_SURFACE.search(body):
                    continue
                arrays = _array_params(params)
                if not arrays:
                    continue
                pnames = _param_names(params)
                count_names = {p for p in pnames if _COUNT_NAME.search(p)}
                if not count_names:
                    continue
                for count in count_names:
                    loop_uses_count = re.search(
                        r"\b(?:for|while)\b[\s\S]{0,180}<\s*" + re.escape(count) + r"\b",
                        body,
                        re.I,
                    )
                    if not loop_uses_count:
                        continue
                    indexed_arrays = [
                        arr for arr in arrays
                        if re.search(re.escape(arr) + r"\s*\[\s*(?:i|j|k|idx|index)\s*\]", body)
                    ]
                    if not indexed_arrays:
                        continue
                    equality = any(
                        re.search(
                            re.escape(count) + r"\s*==\s*" + re.escape(arr) + r"\s*\.\s*length"
                            r"|" + re.escape(arr) + r"\s*\.\s*length\s*==\s*" + re.escape(count),
                            body,
                        )
                        for arr in indexed_arrays
                    )
                    count_bound_to_hash = re.search(
                        r"(abi\.encode|keccak256)[\s\S]{0,260}\b" + re.escape(count) + r"\b",
                        body,
                        re.I,
                    )
                    if equality or count_bound_to_hash:
                        continue
                    out.append(_finding(
                        self.name,
                        "proof_settlement_count_unbound",
                        f"Proof verification and settlement loop use an unbound count: {fname}",
                        (
                            f"`{fname}` verifies proof/public-input data but settles only the first "
                            f"`{count}` item(s) from array input `{indexed_arrays[0]}`. The count is "
                            "not equality-bound to the array length or visibly committed into the "
                            "proof input hash, so the circuit may prove a different transaction set "
                            "than the L1 loop executes (Aztec Connect numRealTxs class)."
                        ),
                        9.0,
                        4.5,
                        "critical",
                        "zk_settlement_boundary",
                        fname,
                        tests=[
                            "Inspect circuit/public inputs: confirm the count and the exact settled item list are committed.",
                            "Fork/local PoC: prove a batch with extra items beyond the L1 count and confirm unbacked credit/withdrawal.",
                        ],
                        extra={"file": path, "count_param": count, "array_params": indexed_arrays},
                    ))
                    break
        return out


# --------------------------------------------------------------------------- #
# MAP/Butter retry variants: replay key lacks bridge domain binding
# --------------------------------------------------------------------------- #
_BRIDGE_FN = re.compile(r"(retry|relay|execute|receive|process|message|packet|bridge)", re.I)
_PROCESSED_KEY = re.compile(r"(processed|used|consumed|replayed|executed)\w*\s*\[", re.I)
_HASH_ARGS = re.compile(
    r"keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\(((?:[^()]|\([^()]*\))*)\)\s*\)",
    re.I,
)
_DOMAIN_ANCHOR = re.compile(
    r"block\.chainid|address\s*\(\s*this\s*\)|source|src|origin|fromChain|toChain|"
    r"dst|dest|domain|eid|chainSelector|sender|peer|remote|nonce|sequence|packetId|messageId",
    re.I,
)


class BridgeRetryDomainBindingDetector(Detector):
    name = "bridge_retry_domain_binding"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not (_BRIDGE_FN.search(fname) or _BRIDGE_FN.search(body)):
                    continue
                if not _PROCESSED_KEY.search(body):
                    continue
                for hm in _HASH_ARGS.finditer(body):
                    args = hm.group(1)
                    anchors = {m.group(0).lower() for m in _DOMAIN_ANCHOR.finditer(args)}
                    # A replay/processed key should bind at least local domain,
                    # remote provenance, and nonce/message id. One anchor is not enough.
                    if len(anchors) >= 3:
                        continue
                    out.append(_finding(
                        self.name,
                        "bridge_retry_hash_missing_domain",
                        f"Bridge retry/replay hash lacks full domain binding: {fname}",
                        (
                            f"`{fname}` records a processed/retry hash, but the hashed fields "
                            "do not visibly bind local contract/chain, remote source/peer, and "
                            "nonce/message id together. A forged or colliding retry payload can "
                            "be accepted as already authenticated or not-yet-processed (MAP/Butter "
                            "retry-verification class)."
                        ),
                        9.0,
                        5.0,
                        "critical",
                        "bridge_retry_replay_domain",
                        fname,
                        tests=[
                            "Confirm the replay key includes source chain, source sender, destination chain/contract, nonce/message id, and payload hash.",
                            "Try a fork/unit PoC with the same payload under a different source/domain; acceptance means exploitable.",
                        ],
                        extra={"file": path, "hash_args": args[:300]},
                    ))
                    break
        return out


# --------------------------------------------------------------------------- #
# FutureSwap/Kipseli class: unit and decimals mismatch in valuation math
# --------------------------------------------------------------------------- #
_ORACLE_PRICE = re.compile(r"oracle|latestAnswer|latestRoundData|getPrice|priceOf|assetPrice|answer", re.I)
_FIXED_SCALE = re.compile(r"\b(1e18|1e8|10\s*\*\*\s*18|10\s*\*\*\s*8|1_000_000_000_000_000_000)\b")
_VALUE_MATH = re.compile(r"\*|/|mulDiv|wmul|wdiv", re.I)


class DecimalUnitMismatchDetector(Detector):
    name = "decimal_unit_mismatch"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        has_decimals_helper = bool(re.search(r"\bdecimals\s*\(|IERC20Metadata", full))
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if re.search(r"\b(private|internal)\b", tail) and not re.search(r"view|pure", tail, re.I):
                    continue
                if not (_ORACLE_PRICE.search(body) and _FIXED_SCALE.search(body) and _VALUE_MATH.search(body)):
                    continue
                if re.search(r"\bdecimals\s*\(|10\s*\*\*\s*\w*decimals|scaleDecimals|normalize", body, re.I):
                    continue
                if has_decimals_helper and re.search(r"normalize|scale|toWad|fromWad|convert", full, re.I):
                    continue
                out.append(_finding(
                    self.name,
                    "oracle_math_hardcoded_scale_no_decimals",
                    f"Oracle/value math uses a hard-coded scale without token decimal normalization: {fname}",
                    (
                        f"`{fname}` combines oracle/price data with token amounts using a hard-coded "
                        "1e18/1e8-style scale, but this path does not read token decimals or call a "
                        "normalization helper. Tokens/oracles with different units can be overvalued "
                        "or undervalued (FutureSwap/Kipseli decimal-unit mismatch class)."
                    ),
                    7.5,
                    4.5,
                    "high",
                    "decimal_unit_mismatch",
                    fname,
                    tests=[
                        "Run unit tests with 6, 8, and 18 decimal tokens and oracle feeds; compare expected normalized value.",
                        "Confirm every oracle answer and token amount is converted into the same unit before collateral/quote math.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Little Boy Plus class: zero-value transferFrom succeeds and gates a reward
# --------------------------------------------------------------------------- #
_TRANSFER_FROM = re.compile(r"(?:safeTransferFrom|transferFrom)\s*\([^;]*\b([A-Za-z_]\w*)\b[^;]*\)", re.I)
_ZERO_GUARD = re.compile(
    r"(require|if)\s*\([^;{]*(amount|amt|value|qty)\w*\s*(>\s*0|!=\s*0)"
    r"|0\s*<\s*(amount|amt|value|qty)\w*",
    re.I,
)
_ZERO_SINK = re.compile(
    r"_mint\s*\(|claimed\s*\[|unlocked\s*\[|isPaid\s*\[|eligible\s*\[|reward|bonus|airdrop|withdraw",
    re.I,
)


class ZeroValueTransferFromBypassDetector(Detector):
    name = "zero_value_transferfrom_bypass"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not re.search(r"\b(public|external)\b", tail):
                    continue
                if not re.search(r"(claim|buy|mint|unlock|redeem|airdrop|reward|execute)", fname, re.I):
                    continue
                pnames = _param_names(params)
                amount_params = {p for p in pnames if re.search(r"amount|amt|value|qty", p, re.I)}
                if not amount_params:
                    continue
                if _ZERO_GUARD.search(body):
                    continue
                transfer_uses_amount = any(
                    re.search(r"transferFrom\s*\([^;]*\b" + re.escape(p) + r"\b", body)
                    for p in amount_params
                )
                if transfer_uses_amount and _ZERO_SINK.search(body):
                    out.append(_finding(
                        self.name,
                        "zero_transferfrom_gates_value_path",
                        f"Zero-value transferFrom can satisfy a value/reward gate: {fname}",
                        (
                            f"`{fname}` accepts an amount-like parameter, calls transferFrom with it, "
                            "and then marks eligibility or mints/unlocks/rewards value without an "
                            "amount > 0 guard. Many ERC20s return success for transferFrom(..., 0), "
                            "letting attackers pass the payment gate for free (Little Boy Plus class)."
                        ),
                        7.5,
                        5.0,
                        "high",
                        "zero_value_transfer_gate",
                        fname,
                        tests=[
                            "Call with amount=0 using a normal ERC20; confirm the post-transfer reward/eligibility path still executes.",
                            "Confirm the transferred amount, not a separate reward variable, determines all credited value.",
                        ],
                        extra={"file": path, "amount_params": sorted(amount_params)},
                    ))
        return out


# --------------------------------------------------------------------------- #
# Thetanuts/index vault class: component-share accounting from live balances
# --------------------------------------------------------------------------- #
_COMPONENT_LOOP = re.compile(r"\bfor\s*\(|\bwhile\s*\(", re.I)
_COMPONENT_HINT = re.compile(r"components|assets|tokens|underlyings|legs|constituents", re.I)
_BALANCE_SHARE = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)[^;]*(?:shares|share|amount|supply|totalSupply)"
    r"|(?:shares|share|amount)[^;]*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
    re.I,
)
_BURN_OR_DEBIT = re.compile(r"_burn\s*\(|burn\s*\(|shares?\s*\[[^\]]+\]\s*-|balanceOf\s*\[[^\]]+\]\s*-", re.I)


class ComponentShareAccountingDetector(Detector):
    name = "component_share_accounting"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not re.search(r"(redeem|withdraw|exit|burn|settle)", fname, re.I):
                    continue
                if not (_COMPONENT_LOOP.search(body) and _COMPONENT_HINT.search(body)):
                    continue
                if not (_BALANCE_SHARE.search(body) and re.search(r"safeTransfer|transfer", body)):
                    continue
                first_transfer = re.search(r"safeTransfer|transfer", body)
                first_burn = _BURN_OR_DEBIT.search(body)
                burn_before_transfer = bool(first_burn and first_transfer and first_burn.start() < first_transfer.start())
                uses_internal_assets = bool(re.search(r"storedAssets|componentBalances|managedAssets|assetBalance", body))
                if burn_before_transfer and uses_internal_assets:
                    continue
                out.append(_finding(
                    self.name,
                    "component_redeem_live_balance_share_math",
                    f"Component redemption uses live balances/share math before robust share debit: {fname}",
                    (
                        f"`{fname}` loops over component assets and computes payouts from live "
                        "token.balanceOf(address(this)) share math before a clearly prior share "
                        "burn/debit/internal-balance update. Donations, reentrancy, or component "
                        "balance skew can inflate what each share redeems (Thetanuts/index-vault "
                        "component-share accounting class)."
                    ),
                    8.0,
                    4.5,
                    "high",
                    "component_share_accounting",
                    fname,
                    tests=[
                        "Unit/fork PoC: donate one component or reenter before share burn; check whether redeemable component amounts inflate.",
                        "Confirm shares are burned/debited before transfers and component balances use internal accounting, not raw live balances.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Kelp-style bridge config: single verifier / threshold of one
# --------------------------------------------------------------------------- #
_BRIDGE_CONFIG = re.compile(r"LayerZero|DVN|verifier|validator|oracle|relayer|threshold|signature|multisig", re.I)
_ONE_OF_ONE = re.compile(
    r"(required\w*|threshold|min\w*|quorum|confirmations?|signatures?)\s*=\s*1\b|"
    r"(required\w*|threshold|min\w*|quorum|confirmations?|signatures?)\s*:\s*1\b|"
    r"new\s+address\s*\[\s*\]\s*\(\s*1\s*\)",
    re.I,
)


class SingleVerifierBridgeConfigDetector(Detector):
    name = "single_verifier_bridge_config"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not _BRIDGE_CONFIG.search(body + " " + fname):
                    continue
                if not _ONE_OF_ONE.search(body):
                    continue
                guarded = bool(re.search(r"onlyOwner|onlyRole|onlyAdmin|onlyGovernance|timelock", tail + body, re.I))
                out.append(_finding(
                    self.name,
                    "bridge_single_verifier_or_threshold_one",
                    f"Bridge/security config allows a one-of-one verifier threshold: {fname}",
                    (
                        f"`{fname}` appears to configure a bridge/verifier/signature threshold of one "
                        "or a one-element verifier set. That is a centralization and liveness risk: "
                        "compromise or data isolation of the single verifier can authorize forged "
                        "messages (KelpDAO LayerZero 1-of-1 verifier class)."
                    ),
                    8.0,
                    4.0,
                    "high",
                    "single_verifier_bridge_config",
                    fname,
                    tests=[
                        "Read live config and confirm required verifier/signature threshold and verifier set size.",
                        "If this is a documented trust assumption, mark as centralization risk; if unguarded/user-settable, escalate.",
                    ],
                    extra={"file": path, "has_access_control": guarded, "documented_centralization": guarded},
                ))
        return out


# --------------------------------------------------------------------------- #
# Transit/Squid style allowance drains: arbitrary target+calldata router
# --------------------------------------------------------------------------- #
_CALLDATA_PARAM = re.compile(r"\bbytes\s+(?:calldata|memory)?\s*([A-Za-z_]\w*)", re.I)
_TARGET_PARAM = re.compile(r"\baddress\s+(?:payable\s+)?([A-Za-z_]\w*)", re.I)
_LOW_CALL = re.compile(r"\.call\s*(?:\{[^}]*\})?\s*\(", re.I)
_ALLOWLIST = re.compile(r"allowlist|whitelist|approvedTargets|trustedTargets|isAllowed|selector|bytes4|msg\.sig", re.I)


class AllowanceDrainRouterDetector(Detector):
    name = "allowance_drain_router"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not re.search(r"\b(public|external)\b", tail):
                    continue
                if re.search(r"onlyOwner|onlyRole|onlyAdmin|onlyGovernance", tail, re.I):
                    continue
                data_params = set(_CALLDATA_PARAM.findall(params))
                target_params = set(_TARGET_PARAM.findall(params))
                if not data_params or not target_params or not _LOW_CALL.search(body):
                    continue
                if _ALLOWLIST.search(body):
                    continue
                target_used = any(
                    re.search(r"\b" + re.escape(t) + r"\b\s*\.\s*call", body)
                    or re.search(r"Address\s*\.\s*functionCall\s*\(\s*" + re.escape(t), body)
                    for t in target_params
                )
                data_used = any(re.search(r"\b" + re.escape(d) + r"\b", body) for d in data_params)
                if not (target_used and data_used):
                    continue
                out.append(_finding(
                    self.name,
                    "router_unfiltered_target_and_calldata",
                    f"Router forwards caller-supplied target and calldata with no allowlist: {fname}",
                    (
                        f"`{fname}` is an unguarded router/multicall path that forwards both a "
                        "caller-supplied target address and caller-supplied calldata without a "
                        "target/selector allowlist. If users have standing approvals to this "
                        "router or its approve-governance dependency, the attacker can encode "
                        "transferFrom(victim, attacker, amount) and drain allowances (Transit/"
                        "SquidRouter/SwapNet class)."
                    ),
                    8.5,
                    6.0,
                    "high",
                    "allowance_drain_router",
                    fname,
                    lead_only=False,
                    tests=[
                        "Fork PoC: victim approves router/dependency, attacker calls router with token target + transferFrom calldata.",
                        "Confirm target and selector are constrained to a safe allowlist and that payer/from is msg.sender-bound.",
                    ],
                    extra={"file": path},
                ))
        return out
