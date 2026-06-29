"""Ultra-deep v2 detectors for 2026 exploit variants.

These rules are intentionally profile-isolated. They encode high-signal
structural probes from the 2020-2026 incident corpus that were not covered well
by the first ultra-deep wave: settlement/proof boundary drift, bridge retry
domain binding, unit mismatches, zero-value transferFrom gates, component-share
accounting, single-verifier bridge configs, allowance-drain routers,
zero-transfer reward checkpoint farming, classic bridge/root failures, compiler
windows, thin-liquidity oracle surfaces, exchange-rate donations, CLMM boundary
math, invariant precision loss, unsafe mint math, flash-cycle rounding, and
custody/provenance risks.
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
# Royal Royalties class: zero ERC1155/LDA transfer stacks reward checkpoints
# --------------------------------------------------------------------------- #
_TRANSFER_HOOK_NAME = re.compile(
    r"beforeLdaTransfer|beforeTokenTransfer|_beforeTokenTransfer|afterTokenTransfer|"
    r"_afterTokenTransfer|onERC1155Received|onERC1155BatchReceived|transferHook",
    re.I,
)
_SETTLE_CALL = re.compile(r"\b(_settle\w*|settle\w*|_checkpoint\w*|checkpoint\w*|_record\w*)\s*\(")
_RECORD_APPEND = re.compile(
    r"(_NUM_\w*RECORD\w*|\w*RecordCount|\w*CheckpointCount|\w*Index|\w*Nonce)\w*"
    r"\s*(?:=|\+=|\+\+)|\.push\s*\(|\[\s*\w+\s*\]\s*=\s*\w*Record\s*\(",
    re.I,
)
_REWARD_RECORD_WRITE = re.compile(
    r"(_UCR_|_UCE_|_TCR_|\w*Reward\w*|\w*Claim\w*|\w*Royal\w*|\w*Cumulative\w*|"
    r"\w*Checkpoint\w*|\w*Record\w*)",
    re.I,
)
_HOOK_ZERO_GUARD = re.compile(
    r"(amount|amt|qty|quantity)\w*\s*>\s*0|"
    r"(amount|amt|qty|quantity)\w*\s*!=\s*0|"
    r"0\s*<\s*(amount|amt|qty|quantity)\w*|"
    r"from\s*!=\s*to|to\s*!=\s*from",
    re.I,
)
_CHECKPOINT_NOOP_GUARD = re.compile(
    r"return\s*;|"
    r"last\w*\.(?:depositId|balance|ldaBalance|value)\s*==|"
    r"==\s*last\w*\.(?:depositId|balance|ldaBalance|value)|"
    r"new\w*Value\s*==\s*last\w*\.value|"
    r"lastDepositId\s*==\s*lastSettledDepositId",
    re.I,
)


class ZeroTransferRewardCheckpointDetector(Detector):
    name = "zero_transfer_reward_checkpoint"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            bodies = {
                fname: (params, tail, body)
                for fname, params, tail, body in iter_function_bodies(src)
            }
            for hook_name, params, tail, body in iter_function_bodies(src):
                if not _TRANSFER_HOOK_NAME.search(hook_name):
                    continue
                if not re.search(r"\b(public|external|internal)\b", tail):
                    continue
                # ERC1155 and some project hooks allow amount=0 transfers. Hooks
                # that do not receive an amount cannot filter zero transfers.
                amount_params = {
                    p for p in _param_names(params)
                    if re.search(r"amount|value|qty|quantity", p, re.I)
                }
                hook_has_zero_guard = bool(amount_params and _HOOK_ZERO_GUARD.search(body))
                if hook_has_zero_guard:
                    continue

                callees = [
                    m.group(1)
                    for m in _SETTLE_CALL.finditer(body)
                    if m.group(1) in bodies
                ]
                if not callees:
                    continue

                for callee in callees:
                    _cparams, _ctail, cbody = bodies[callee]
                    appends_record = _RECORD_APPEND.search(cbody) and _REWARD_RECORD_WRITE.search(cbody)
                    if not appends_record:
                        continue
                    # A no-op guard must live on the appending path itself. A
                    # caller-only guard is not enough when the hook lacks amount.
                    if _CHECKPOINT_NOOP_GUARD.search(cbody):
                        continue
                    out.append(_finding(
                        self.name,
                        "zero_transfer_stacks_reward_records",
                        f"Transfer hook can append reward checkpoints on zero-value transfers: {hook_name}",
                        (
                            f"`{hook_name}` calls `{callee}` from a token-transfer hook, but the hook "
                            "does not enforce a non-zero transferred amount and the settlement path "
                            "appends/increments reward/accounting records without a duplicate/no-op "
                            "guard. ERC1155-style zero-value transfers can repeatedly create "
                            "checkpoints for the same balance/deposit cursor, then claim/settlement "
                            "math may count the same rewards multiple times (Royal Royalties Polygon "
                            "class)."
                        ),
                        9.0,
                        6.0,
                        "high",
                        "zero_transfer_reward_checkpoint",
                        hook_name,
                        lead_only=False,
                        tests=[
                            "Fork PoC: perform many ERC1155/LDA safeTransferFrom calls with amount=0 and confirm the checkpoint count increases.",
                            "After deposits expire or become claimable, call settlement/claim and compare payout against a no-transfer baseline.",
                            "Confirm the settlement function skips appending when depositId, balance, and cumulative value are unchanged.",
                        ],
                        extra={
                            "file": path,
                            "hook": hook_name,
                            "settlement_function": callee,
                            "amount_params": sorted(amount_params),
                        },
                    ))
                    break
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


# --------------------------------------------------------------------------- #
# Lendf.Me class: ERC777/token hook reentrancy before balance bookkeeping
# --------------------------------------------------------------------------- #
_HOOK_TOKEN_SURFACE = re.compile(
    r"ERC777|IERC777|tokensToSend|tokensReceived|ERC1820|operatorSend|"
    r"safeTransferFrom|transferFrom",
    re.I,
)
_DEPOSIT_LIKE = re.compile(r"(deposit|supply|mint|collateral|repay|join|stake)", re.I)
_TOKEN_TRANSFER_IN = re.compile(r"(?:safeTransferFrom|transferFrom)\s*\(", re.I)
_BALANCE_BOOKKEEP = re.compile(
    r"\b(accountTokens|balances?|deposits?|shares?|collateral|credits?|principal|"
    r"userInfo|supplied|staked)\w*\s*(?:\[[^\]]+\]\s*)?(?:\.\w+\s*)?(?:=|\+=|-=)",
    re.I,
)
_REENTRANCY_LOCK = re.compile(r"nonReentrant|reentrancyGuard|_status|locked", re.I)


class Erc777HookBalanceBypassDetector(Detector):
    name = "erc777_hook_balance_bypass"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        if not _HOOK_TOKEN_SURFACE.search(full):
            return out
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not re.search(r"\b(public|external)\b", tail):
                    continue
                if not _DEPOSIT_LIKE.search(fname) and not _DEPOSIT_LIKE.search(body):
                    continue
                if _REENTRANCY_LOCK.search(tail + body[:240]):
                    continue
                transfer = _TOKEN_TRANSFER_IN.search(body)
                if not transfer:
                    continue
                write_after = _BALANCE_BOOKKEEP.search(body[transfer.end():])
                write_before = _BALANCE_BOOKKEEP.search(body[:transfer.start()])
                if not write_after or write_before:
                    continue
                out.append(_finding(
                    self.name,
                    "erc777_transfer_hook_before_balance_update",
                    f"Token transfer hook can re-enter before balance bookkeeping: {fname}",
                    (
                        f"`{fname}` pulls tokens with transferFrom/safeTransferFrom before it "
                        "updates protocol balance/share/collateral accounting and no local "
                        "reentrancy lock is visible. ERC777-style tokens invoke sender hooks "
                        "during transferFrom, so a malicious holder can re-enter withdraw/borrow "
                        "logic while the old balance is still trusted (Lendf.Me / imBTC class)."
                    ),
                    9.0,
                    6.0,
                    "critical",
                    "erc777_hook_reentrancy",
                    fname,
                    lead_only=False,
                    tests=[
                        "Fork/unit PoC: use an ERC777-like token whose tokensToSend hook re-enters withdraw/borrow before the deposit accounting write.",
                        "Confirm all balance/share effects happen before transferFrom or the whole protocol shares one reentrancy lock.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# EraLend/Curve class: read-only reentrancy through live reserve/value reads
# --------------------------------------------------------------------------- #
_LIVE_RESERVE_READ = re.compile(
    r"getReserves\s*\(|price_oracle\s*\(|get_virtual_price\s*\(|virtualPrice\s*\(|"
    r"exchangeRateCurrent\s*\(|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"totalSupply\s*\(",
    re.I,
)
_VALUATION_FN = re.compile(r"(price|value|rate|exchange|collateral|liquidat|preview|quote|oracle)", re.I)
_READ_LOCK = re.compile(r"nonReentrantView|reentrantLock|readLock|lockRead|sync\s*\(", re.I)
_CACHE_OR_TWAP = re.compile(r"last\w*Price|cached|TWAP|observe\s*\(|cumulative|block\.timestamp\s*-", re.I)


class ReadOnlyReserveReentrancyDetector(Detector):
    name = "read_only_reserve_reentrancy"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        has_external_interaction = bool(re.search(
            r"\.call\s*\(|safeTransfer|transferFrom|swap\s*\(|mint\s*\(|burn\s*\(",
            full,
            re.I,
        ))
        if not has_external_interaction:
            return out
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, tail, body in iter_function_bodies(src):
                if not re.search(r"\b(public|external)\b", tail):
                    continue
                if not ("view" in tail.lower() or _VALUATION_FN.search(fname)):
                    continue
                if not (_VALUATION_FN.search(fname + " " + body) and _LIVE_RESERVE_READ.search(body)):
                    continue
                if _READ_LOCK.search(tail + body) or _CACHE_OR_TWAP.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "live_reserve_read_without_read_lock",
                    f"Valuation reads live reserves with no read-only reentrancy guard: {fname}",
                    (
                        f"`{fname}` exposes valuation/oracle math from live pool/token reserves "
                        "instead of cached/TWAP state, and the codebase has external interaction "
                        "paths. During a token/pool callback, a read-only reentrant call can observe "
                        "transient reserves and borrow/redeem/liquidate against a false price "
                        "(EraLend / Curve read-only reentrancy class)."
                    ),
                    8.0,
                    4.0,
                    "high",
                    "read_only_reentrancy",
                    fname,
                    tests=[
                        "Build a malicious pool/token callback that calls the valuation function before reserve sync completes.",
                        "Confirm valuation uses cached/TWAP state or a read lock shared with mutating pool paths.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Poly Network class: bridge payload can mutate keeper/validator trust roots
# --------------------------------------------------------------------------- #
_KEEPER_SURFACE = re.compile(
    r"keeper|validator|consensus|committee|epoch|pubkey|publicKey|bookKeeper|"
    r"EthCrossChainData|putCurEpochConPubKeyBytes",
    re.I,
)
_BRIDGE_EXEC_SURFACE = re.compile(r"(execute|relay|process|verify|crossChain|message|payload)", re.I)
_DECODED_TARGET_CALL = re.compile(
    r"abi\.decode[\s\S]{0,420}(target|to|contractAddr|addr|method|selector|data)|"
    r"\b(target|to|contractAddr|addr)\s*\.\s*call\s*\(",
    re.I,
)
_TARGET_SELECTOR_ALLOWLIST = re.compile(
    r"allowlist|whitelist|trustedTargets|allowedSelectors?|onlyCrossChainManager|"
    r"require\s*\([^;]*(target|to|selector|method)[^;]*(==|allowed|trusted)",
    re.I,
)


class BridgeKeeperMutationDetector(Detector):
    name = "bridge_keeper_mutation"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        if not _KEEPER_SURFACE.search(full):
            return out
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, tail, body in iter_function_bodies(src):
                if not re.search(r"\b(public|external)\b", tail):
                    continue
                if not (_BRIDGE_EXEC_SURFACE.search(fname) or _BRIDGE_EXEC_SURFACE.search(body)):
                    continue
                if not _DECODED_TARGET_CALL.search(body):
                    continue
                if _TARGET_SELECTOR_ALLOWLIST.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "bridge_payload_can_call_keeper_mutator",
                    f"Cross-chain payload can target keeper/validator mutation paths: {fname}",
                    (
                        f"`{fname}` decodes a cross-chain payload into a target/method/calldata "
                        "and forwards it without a visible target+selector allowlist, while the "
                        "codebase contains keeper/validator/epoch public-key mutation state. A "
                        "forged message can retarget the trust root and then authorize arbitrary "
                        "unlocks (Poly Network EthCrossChainData class)."
                    ),
                    9.5,
                    5.0,
                    "critical",
                    "bridge_keeper_mutation",
                    fname,
                    tests=[
                        "Trace whether payload target+selector can reach keeper/public-key setters such as putCurEpochConPubKeyBytes.",
                        "Fork/unit PoC: relay a crafted payload that changes the validator set, then authorize an unlock with attacker keys.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Nomad class: zero/unset bridge root accepted by initialization or gate
# --------------------------------------------------------------------------- #
_ROOT_STATE = re.compile(r"(committedRoot|confirmAt|acceptableRoot|knownRoot|rootStatus|messages|roots)", re.I)
_ZERO_ROOT_SET = re.compile(
    r"(confirmAt|acceptableRoot|knownRoot|rootStatus|messages|roots)\w*\s*\[[^\]]+\]\s*=\s*(?:true|1)",
    re.I,
)
_ROOT_GATE_V2 = re.compile(
    r"(require|if)\s*\([^;{]*(confirmAt|acceptableRoot|knownRoot|rootStatus|messages|roots)\w*"
    r"\s*\[[^\]]+\][^;{]*(?:!=\s*0|==\s*true|>\s*0|\))",
    re.I,
)
_ZERO_ROOT_REJECT_V2 = re.compile(
    r"(root|messageHash|leaf|_committedRoot)\w*\s*!=\s*(?:bytes32\s*\(\s*0\s*\)|0x0+\b|0\b)"
    r"|require\s*\([^;]*(root|messageHash|leaf|_committedRoot)\w*[^;]*!=[^;]*(0|bytes32)",
    re.I,
)


class BridgeZeroRootAcceptanceDetector(Detector):
    name = "bridge_zero_root_acceptance"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        if not _ROOT_STATE.search(full) or not re.search(r"bridge|replica|message|merkle|root", full, re.I):
            return out
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, tail, body in iter_function_bodies(src):
                rooty = _ROOT_STATE.search(fname + " " + body)
                if not rooty:
                    continue
                init_sets_root = re.search(r"(init|initialize|upgrade|setRoot|accept)", fname, re.I) and _ZERO_ROOT_SET.search(body)
                process_gates_root = re.search(r"(process|prove|execute|relay|receive|withdraw)", fname, re.I) and _ROOT_GATE_V2.search(body)
                if not (init_sets_root or process_gates_root):
                    continue
                if _ZERO_ROOT_REJECT_V2.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "bridge_zero_or_unset_root_can_be_confirmed",
                    f"Bridge root gate lacks an explicit zero-root rejection: {fname}",
                    (
                        f"`{fname}` writes or trusts a root/status mapping without visibly "
                        "rejecting bytes32(0). If deployment/upgrade initializes the committed "
                        "root to zero, unproven messages can resolve against the confirmed zero "
                        "root and be copied by anyone (Nomad Replica class)."
                    ),
                    9.5,
                    6.0,
                    "critical",
                    "bridge_zero_root",
                    fname,
                    lead_only=False,
                    tests=[
                        "Unit/fork PoC: initialize/upgrade with bytes32(0), then process a forged message whose calculated root is zero.",
                        "Confirm zero roots are rejected on initialization and every processing gate.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Wormhole-style class: caller-supplied verifier/precompile/sysvar trust
# --------------------------------------------------------------------------- #
_VERIFIER_PARAM = re.compile(r"\baddress\s+(?:payable\s+)?(\w*(?:verifier|validator|sysvar|precompile|core|bridge)\w*)", re.I)
_VERIFY_LOW_CALL = re.compile(r"\b\w+\s*\.\s*(?:staticcall|call)\s*\(", re.I)
_VERIFIER_PIN = re.compile(
    r"trustedVerifier|verifiers?\s*\[|allowedVerifier|codehash|extcodehash|"
    r"==\s*(?:WORMHOLE|CORE|VERIFIER|trusted|immutable|address\s*\(\s*verifier)",
    re.I,
)


class VerifierAddressSpoofDetector(Detector):
    name = "verifier_address_spoof"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, _tail, body in iter_function_bodies(src):
                verifier_params = set(_VERIFIER_PARAM.findall(params))
                if not verifier_params:
                    continue
                if not re.search(r"verify|signature|vaa|proof|guardian|sysvar", fname + " " + body, re.I):
                    continue
                if not _VERIFY_LOW_CALL.search(body):
                    continue
                if _VERIFIER_PIN.search(body):
                    continue
                if not any(re.search(r"\b" + re.escape(p) + r"\s*\.\s*(?:staticcall|call)\s*\(", body) for p in verifier_params):
                    continue
                out.append(_finding(
                    self.name,
                    "caller_supplied_verifier_address",
                    f"Verification path calls a caller-supplied verifier address: {fname}",
                    (
                        f"`{fname}` accepts a verifier/sysvar/precompile-like address from the "
                        "caller and uses low-level call/staticcall for proof/signature validation "
                        "without a visible allowlist, immutable pin, or codehash/domain check. A "
                        "spoofed verifier can return success for forged messages (Wormhole "
                        "verification-provenance class)."
                    ),
                    9.0,
                    5.0,
                    "critical",
                    "verifier_address_spoof",
                    fname,
                    tests=[
                        "Pass an attacker verifier contract that returns a successful validation tuple and confirm the message path continues.",
                        "Confirm verifier address is immutable/allowlisted and the signed domain binds chain, contract, and guardian set.",
                    ],
                    extra={"file": path, "verifier_params": sorted(verifier_params)},
                ))
        return out


# --------------------------------------------------------------------------- #
# Curve 2023 class: Vyper nonreentrant compiler versions with broken locks
# --------------------------------------------------------------------------- #
_VYPER_BAD_VERSION = re.compile(r"#\s*@version\s+(0\.2\.15|0\.2\.16|0\.3\.0)\b", re.I)
_VYPER_NONREENTRANT = re.compile(r"@nonreentrant(?:\s*\(|\b)", re.I)


class VyperNonreentrantCompilerDetector(Detector):
    name = "vyper_nonreentrant_compiler"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            vm = _VYPER_BAD_VERSION.search(src)
            if not vm or not _VYPER_NONREENTRANT.search(src):
                continue
            first_fn = ""
            fm = re.search(r"def\s+([A-Za-z_]\w*)\s*\(", src)
            if fm:
                first_fn = fm.group(1)
            out.append(_finding(
                self.name,
                "vyper_broken_nonreentrant_version",
                f"Vyper {vm.group(1)} nonreentrant lock compiler window: {path}",
                (
                    f"`{path}` declares Vyper {vm.group(1)} and uses @nonreentrant. Vyper "
                    "0.2.15, 0.2.16, and 0.3.0 had a compiler bug that could make "
                    "nonreentrancy locks ineffective, which enabled the Curve pool drains."
                ),
                9.0,
                7.0,
                "critical",
                "vyper_nonreentrant_compiler",
                first_fn,
                lead_only=False,
                tests=[
                    "Confirm deployed bytecode compiler metadata is Vyper 0.2.15/0.2.16/0.3.0.",
                    "Recompile with a fixed Vyper version and run a reentrancy PoC against the old bytecode.",
                ],
                extra={"file": path, "vyper_version": vm.group(1)},
            ))
        return out


# --------------------------------------------------------------------------- #
# bZx/Harvest/Cream/Mango/Polter class: thin-liquidity spot oracle
# --------------------------------------------------------------------------- #
_SPOT_ORACLE_SOURCE = re.compile(
    r"getReserves\s*\(|slot0\s*\(|getAmountsOut\s*\(|getAmountOut\s*\(|"
    r"price_oracle\s*\(|get_dy\s*\(|get_p\s*\(",
    re.I,
)
_ORACLE_SINK = re.compile(r"borrow|liquidat|collateral|mint|redeem|reward|vault|share|price|value", re.I)
_LIQUIDITY_DEPTH_GUARD = re.compile(
    r"minLiquidity|minReserve|minimumReserve|liquidityThreshold|depth|TWAP|observe\s*\(|"
    r"cumulative|secondsAgo|timeWeighted|Chainlink|latestRoundData",
    re.I,
)


class ThinLiquiditySpotOracleDetector(Detector):
    name = "thin_liquidity_spot_oracle"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, _tail, body in iter_function_bodies(src):
                if not (_SPOT_ORACLE_SOURCE.search(body) and _ORACLE_SINK.search(fname + " " + body)):
                    continue
                if _LIQUIDITY_DEPTH_GUARD.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "thin_pool_spot_oracle_no_depth_or_twap",
                    f"Spot AMM oracle lacks TWAP/liquidity-depth guards: {fname}",
                    (
                        f"`{fname}` prices collateral/rewards/shares from a spot AMM read but "
                        "does not visibly enforce reserve depth, liquidity thresholds, or a TWAP. "
                        "A flash loan can skew a thin pool for one transaction and borrow/redeem/"
                        "liquidate against the fake price (bZx, Harvest, Cream, Mango, Polter class)."
                    ),
                    8.5,
                    5.5,
                    "high",
                    "thin_liquidity_oracle",
                    fname,
                    tests=[
                        "Fork: flash-swap/flash-loan to skew the pool, then call the borrow/redeem/liquidation path.",
                        "Confirm the oracle enforces TWAP plus minimum liquidity/depth for every route component.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Hundred/zkLend class: lending exchange-rate/accumulator donation
# --------------------------------------------------------------------------- #
_EXCHANGE_RATE_SURFACE = re.compile(
    r"exchangeRate|lending_accumulator|accumulator|borrowIndex|totalBorrows|"
    r"totalReserves|cashPrior|getCash|cToken|hToken",
    re.I,
)
_DONATION_BALANCE = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|getCashPrior\s*\(|getCash\s*\(",
    re.I,
)
_SUPPLY_DIVISION = re.compile(r"/\s*(?:totalSupply|totalShares|_totalSupply|supply)\b", re.I)
_DONATION_MITIGATION = re.compile(
    r"internalCash|storedCash|cashBalance|virtualShares|deadShares|MINIMUM_LIQUIDITY|"
    r"exchangeRateMantissa\s*=\s*initial|require\s*\([^;]*(totalSupply|supply)[^;]*>\s*0",
    re.I,
)


class LendingExchangeRateDonationDetector(Detector):
    name = "lending_exchange_rate_donation"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        if not _EXCHANGE_RATE_SURFACE.search(full):
            return out
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, _tail, body in iter_function_bodies(src):
                if not _EXCHANGE_RATE_SURFACE.search(fname + " " + body):
                    continue
                if not (_DONATION_BALANCE.search(body) and _SUPPLY_DIVISION.search(body)):
                    continue
                if _DONATION_MITIGATION.search(body + " " + full):
                    continue
                out.append(_finding(
                    self.name,
                    "exchange_rate_from_donatable_cash",
                    f"Lending exchange rate uses donatable cash divided by supply: {fname}",
                    (
                        f"`{fname}` derives an exchange rate/accumulator from live contract cash "
                        "or token.balanceOf(address(this)) divided by total supply, without "
                        "visible virtual/dead-share or internal-cash protection. Direct donations "
                        "to an empty or thin market can inflate the rate and drain borrows/"
                        "withdrawals (Hundred Finance / zkLend lending accumulator class)."
                    ),
                    8.5,
                    6.0,
                    "high",
                    "lending_exchange_rate_donation",
                    fname,
                    lead_only=False,
                    tests=[
                        "Fork/unit PoC: leave the market thin, donate underlying directly, then mint/redeem/borrow against the inflated exchange rate.",
                        "Confirm total cash is internally accounted or protected by virtual/dead shares and minimum liquidity.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# KyberSwap Elastic class: CLMM tick-boundary/rounding mismatch
# --------------------------------------------------------------------------- #
_CLMM_SURFACE = re.compile(r"sqrtP|sqrtPrice|tick|liquidity|swapStep|nextSqrt|deltaL|baseL", re.I)
_CLMM_ROUNDING = re.compile(r"mulDiv|FullMath|roundingUp|ceil|delta|calcFinalPrice|computeSwapStep", re.I)
_BOUNDARY_CROSS_GUARD = re.compile(
    r"(nextSqrt\w*|sqrtP\w*)\s*(?:==|>=|<=)\s*(target|next|boundary|sqrtPrice)\w*|"
    r"crossTick\s*\(|_cross\s*\(|recomputeLiquidity|require\s*\([^;]*(tick|sqrt)[^;]*(<=|>=)",
    re.I,
)


class ClmmTickBoundaryRoundingDetector(Detector):
    name = "clmm_tick_boundary_rounding"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, _tail, body in iter_function_bodies(src):
                if not re.search(r"(swap|compute|calc|getNext|update|cross)", fname, re.I):
                    continue
                if not (_CLMM_SURFACE.search(body) and _CLMM_ROUNDING.search(body)):
                    continue
                if _BOUNDARY_CROSS_GUARD.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "clmm_boundary_rounding_without_cross_guard",
                    f"CLMM swap math lacks explicit tick-boundary crossing guard: {fname}",
                    (
                        f"`{fname}` mixes sqrt-price/tick/liquidity rounding math but no explicit "
                        "boundary equality/crossing guard is visible. Concentrated-liquidity AMMs "
                        "can desynchronize liquidity and price at exact tick boundaries when "
                        "rounding picks the wrong side (KyberSwap Elastic class)."
                    ),
                    8.5,
                    4.5,
                    "high",
                    "clmm_tick_boundary",
                    fname,
                    tests=[
                        "Unit/fuzz exact tick-boundary swaps: price equal to target tick, one wei below, and one wei above.",
                        "Assert liquidity is crossed exactly once and invariant value cannot be inflated by repeated boundary swaps.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Balancer/forks class: invariant precision loss and wrong rounding direction
# --------------------------------------------------------------------------- #
_INVARIANT_SURFACE = re.compile(r"invariant|amp|amplification|BPT|poolToken|scalingFactor|rateProvider|stable", re.I)
_DIV_BEFORE_MUL = re.compile(r"\b\w+\s*/\s*\w+\s*\*\s*\w+|\(\s*[^()]{1,80}/[^()]{1,80}\)\s*\*", re.I)
_PRECISION_SAFE = re.compile(r"mulDiv|divDown|divUp|mulDown|mulUp|FixedPoint|LogExpMath|rounding", re.I)


class InvariantPrecisionLossDetector(Detector):
    name = "invariant_precision_loss"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, _tail, body in iter_function_bodies(src):
                if not _INVARIANT_SURFACE.search(fname + " " + body):
                    continue
                if not _DIV_BEFORE_MUL.search(body):
                    continue
                if _PRECISION_SAFE.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "invariant_division_before_multiplication",
                    f"Invariant/pool-token math divides before multiplying: {fname}",
                    (
                        f"`{fname}` performs invariant/rate/BPT math with division before later "
                        "multiplication and no fixed-point rounding helper. Stable-pool invariant "
                        "math is sensitive to rounding direction; truncation can deflate pool-token "
                        "price or misprice exits (Balancer V2/forks precision-loss class)."
                    ),
                    8.0,
                    4.5,
                    "high",
                    "invariant_precision_loss",
                    fname,
                    tests=[
                        "Fuzz small balances and highly imbalanced pools; compare against a high-precision reference implementation.",
                        "Check every invariant step uses explicit up/down rounding appropriate to whether users mint or burn BPT.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# yETH class: unsafe unchecked mint/share math
# --------------------------------------------------------------------------- #
_MINT_FN = re.compile(r"(mint|deposit|issue|wrap|join)", re.I)
_UNSAFE_MINT_MATH = re.compile(r"unchecked\s*\{[\s\S]{0,600}(?:\*|\+|/)|(?:\*|/)[^;]{0,160}_mint", re.I)
_MINT_SINK = re.compile(r"_mint\s*\([^,]+,\s*([A-Za-z_]\w*)\s*\)", re.I)
_MINT_MATH_GUARD = re.compile(r"mulDiv|SafeCast|Math\.|require\s*\([^;]*(shares|minted|amountOut)[^;]*(>|>=)|cap|maxSupply|minShares", re.I)


class UnsafeMintMathDetector(Detector):
    name = "unsafe_mint_math"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, tail, body in iter_function_bodies(src):
                if not re.search(r"\b(public|external)\b", tail) or not _MINT_FN.search(fname):
                    continue
                mint = _MINT_SINK.search(body)
                if not mint:
                    continue
                if not _UNSAFE_MINT_MATH.search(body):
                    continue
                if _MINT_MATH_GUARD.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "unchecked_mint_amount_math",
                    f"Mint amount is derived through unsafe math without caps/slippage guards: {fname}",
                    (
                        f"`{fname}` mints `{mint.group(1)}` after unchecked or ad-hoc arithmetic "
                        "without visible mulDiv/SafeCast/cap/min-share guards. A crafted amount, "
                        "rate, or supply edge can over-mint shares/tokens (yETH unsafe-math class)."
                    ),
                    8.0,
                    4.5,
                    "high",
                    "unsafe_mint_math",
                    fname,
                    tests=[
                        "Fuzz amount/rate/supply near zero, max uint, and precision boundaries; assert minted value is monotonic and capped.",
                        "Compare against a checked high-precision reference and require minSharesOut from the caller.",
                    ],
                    extra={"file": path, "minted_var": mint.group(1)},
                ))
        return out


# --------------------------------------------------------------------------- #
# Bunni class: withdraw rounding amplified by flash-cycle repetition
# --------------------------------------------------------------------------- #
_ROUND_UP_MATH = re.compile(
    r"mulDivRoundingUp|ceilDiv|roundUp|\+\s*\w+\s*-\s*1\s*\)\s*/|/\s*\w+\s*\+\s*1",
    re.I,
)
_WITHDRAW_TRANSFER = re.compile(r"safeTransfer|transfer\s*\(|sendValue|\.call\s*\{", re.I)


class FlashCycleRoundingWithdrawDetector(Detector):
    name = "flash_cycle_rounding_withdraw"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, _tail, body in iter_function_bodies(src):
                if not re.search(r"(withdraw|redeem|burn|exit|remove)", fname, re.I):
                    continue
                if not (_ROUND_UP_MATH.search(body) and _WITHDRAW_TRANSFER.search(body)):
                    continue
                transfer = _WITHDRAW_TRANSFER.search(body)
                debit = _BURN_OR_DEBIT.search(body)
                debit_before_transfer = bool(debit and transfer and debit.start() < transfer.start())
                if debit_before_transfer and re.search(r"dust|minOut|roundDown|mulDiv\(", body, re.I):
                    continue
                out.append(_finding(
                    self.name,
                    "withdraw_rounds_up_before_robust_debit",
                    f"Withdraw path rounds user payout up and can be cycled: {fname}",
                    (
                        f"`{fname}` uses round-up/ceil math for a withdrawal payout and transfers "
                        "before a clearly robust burn/debit/dust guard. Tiny rounding gains can be "
                        "amplified by flash-loan deposit/withdraw loops until pool accounting is "
                        "drained (Bunni withdraw-rounding class)."
                    ),
                    8.0,
                    4.5,
                    "high",
                    "flash_cycle_rounding_withdraw",
                    fname,
                    tests=[
                        "Fuzz repeated deposit->withdraw cycles with minimal shares and flash-loan-sized liquidity.",
                        "Require rounding direction favors the pool on exits and burn/debit occurs before transfer.",
                    ],
                    extra={"file": path},
                ))
        return out


# --------------------------------------------------------------------------- #
# Bybit/Safe supply-chain class: multisig signed delegatecall payload
# --------------------------------------------------------------------------- #
_MULTISIG_SURFACE = re.compile(r"checkSignatures|threshold|owners|multisig|Safe|execTransaction|signature", re.I)
_DELEGATECALL_USER_PAYLOAD = re.compile(r"delegatecall\s*\([^;]*(data|payload|calldata|operation|to|target)", re.I)
_DELEGATECALL_BLOCK = re.compile(r"operation\s*!=\s*\w*DelegateCall|require\s*\([^;]*delegatecall[^;]*(false|disabled)|allowlist|moduleWhitelist", re.I)


class MultisigDelegatecallPayloadDetector(Detector):
    name = "multisig_delegatecall_payload"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        if not _MULTISIG_SURFACE.search(full):
            return out
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, _tail, body in iter_function_bodies(src):
                if not _MULTISIG_SURFACE.search(fname + " " + body):
                    continue
                if not _DELEGATECALL_USER_PAYLOAD.search(body):
                    continue
                if _DELEGATECALL_BLOCK.search(body):
                    continue
                out.append(_finding(
                    self.name,
                    "multisig_signed_delegatecall_payload",
                    f"Multisig can execute signed delegatecall payloads: {fname}",
                    (
                        f"`{fname}` verifies multisig-style signatures and can execute "
                        "delegatecall with transaction calldata/target. This is intended in some "
                        "Safe-like wallets, but it means a compromised signing UI or hidden payload "
                        "can mutate wallet storage/implementation while signatures are valid "
                        "(Bybit supply-chain delegatecall class)."
                    ),
                    9.0,
                    3.5,
                    "critical",
                    "multisig_delegatecall_payload",
                    fname,
                    tests=[
                        "Confirm whether delegatecall is required; if so, require offline calldata decoding and implementation-slot diff checks in signing flow.",
                        "Simulate a delegatecall payload that writes critical wallet storage and confirm signers would see the true calldata.",
                    ],
                    extra={"file": path, "documented_centralization": True, "lead_only": True},
                ))
        return out


# --------------------------------------------------------------------------- #
# BitMart/Ronin/DMM/WazirX class: single-key custody sweep blast radius
# --------------------------------------------------------------------------- #
_CUSTODY_SWEEP_NAME = re.compile(r"(withdrawAll|sweep|rescue|emergencyWithdraw|drain|transferAll)", re.I)
_ALL_FUNDS_TRANSFER = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|address\s*\(\s*this\s*\)\s*\.balance",
    re.I,
)
_SINGLE_ADMIN = re.compile(r"onlyOwner|owner\s*\(\s*\)|msg\.sender\s*==\s*owner|DEFAULT_ADMIN_ROLE", re.I)
_MULTISIG_TIMELOCK_HINT = re.compile(r"timelock|delay|multisig|threshold|guardian|pauseGuardian|Safe", re.I)


class CustodySweepCentralizationDetector(Detector):
    name = "custody_sweep_centralization"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, _params, tail, body in iter_function_bodies(src):
                if not _CUSTODY_SWEEP_NAME.search(fname):
                    continue
                if not (_SINGLE_ADMIN.search(tail + body) and _ALL_FUNDS_TRANSFER.search(body)):
                    continue
                if _MULTISIG_TIMELOCK_HINT.search(tail + body):
                    continue
                out.append(_finding(
                    self.name,
                    "single_admin_can_sweep_custody",
                    f"Single admin path can sweep all custody funds: {fname}",
                    (
                        f"`{fname}` appears to let one owner/admin-controlled path transfer the "
                        "contract's full token/native balance, with no visible timelock, threshold, "
                        "or guardian delay. The Solidity may be intentional, but compromise of that "
                        "key has exchange/hot-wallet blast radius (BitMart, Ronin, DMM, WazirX class)."
                    ),
                    7.0,
                    3.0,
                    "high",
                    "custody_key_blast_radius",
                    fname,
                    tests=[
                        "Read live owner/admin; verify it is a multisig or timelock and not an EOA/hot wallet.",
                        "Confirm sweep paths are delayed, capped, pausable, and monitored with calldata transparency.",
                    ],
                    extra={"file": path, "documented_centralization": True, "lead_only": True},
                ))
        return out



# --------------------------------------------------------------------------- #
# AIDC / OLPC-LABUBU / JUDAO class: deferred burn debt hits AMM pair reserves
# --------------------------------------------------------------------------- #
_PAIR_ID = r"(?:(?:[A-Za-z_]\w*)?(?:pair|pool|amm|uniswap|pancake|lpToken|lpPair)\w*|pair|pool|lp|amm)"
_DEAD_ID = (
    r"(?:(?:[A-Za-z_]\w*)?(?:dead|burn|blackhole|null|zero)\w*|"
    r"address\s*\(\s*0\s*\)|0x0{20,40}|0x0{0,36}dead)"
)
_PAIR_OUT_PATTERNS = (
    re.compile(
        r"(?P<op>(?:super\s*\.\s*)?_update|(?:super\s*\.\s*)?_transfer|_transfer)"
        r"\s*\(\s*(?P<pair>" + _PAIR_ID + r")\s*,\s*(?P<dst>" + _DEAD_ID + r")\s*,",
        re.I,
    ),
    re.compile(r"(?P<op>_burn|burn)\s*\(\s*(?P<pair>" + _PAIR_ID + r")\s*,", re.I),
    re.compile(r"_balances\s*\[\s*(?P<pair>" + _PAIR_ID + r")\s*\]\s*(?:-=|=)", re.I),
)
_SYNC_OR_SKIM = re.compile(r"\.\s*(sync|skim)\s*\(", re.I)
_DEFERRED_BURN_WRITE = re.compile(
    r"\b((?:[A-Za-z_]\w*)?(?:accumulat|pending|queued|deferred)\w*burn\w*)\s*(?:\+=|=)",
    re.I,
)


def _pair_out_evidence(body: str) -> dict | None:
    for pat in _PAIR_OUT_PATTERNS:
        m = pat.search(body)
        if m:
            ev = {"pair_expr": m.groupdict().get("pair") or "pair-like balance"}
            if m.groupdict().get("op"):
                ev["pair_move_op"] = m.group("op")
            if m.groupdict().get("dst"):
                ev["pair_move_destination"] = m.group("dst")
            return ev
    return None


class AmmPairReserveDesyncDetector(Detector):
    name = "amm_pair_reserve_desync"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            burn_debt_vars = {m.group(1) for m in _DEFERRED_BURN_WRITE.finditer(src)}
            for fname, _params, tail, body in iter_function_bodies(src):
                if re.search(r"\b(view|pure)\b", tail, re.I):
                    continue
                pair_ev = _pair_out_evidence(body)
                if not pair_ev or not _SYNC_OR_SKIM.search(body):
                    continue
                uses_deferred_debt = any(var in body for var in burn_debt_vars)
                rule_id = (
                    "deferred_burn_debt_burns_pair_then_sync"
                    if uses_deferred_debt
                    else "pair_balance_burn_then_sync_reserve_desync"
                )
                title = (
                    f"Deferred burn debt is executed against the AMM pair before sync(): {fname}"
                    if uses_deferred_debt
                    else f"AMM pair balance is burned/transferred before sync(): {fname}"
                )
                out.append(_finding(
                    self.name,
                    rule_id,
                    title,
                    (
                        f"`{fname}` force-moves or burns tokens out of a pair-like address "
                        "and immediately calls pair.sync()/skim(). If this path is reachable "
                        "from a sell/transfer hook or a deferred burn accumulator, an attacker "
                        "can shrink the token reserve used by the AMM and swap out the paired "
                        "asset at an artificial price. This covers the AIDC and OLPC/LABUBU "
                        "2026 reserve-desync family."
                    ),
                    9.3 if uses_deferred_debt else 9.0,
                    8.2 if uses_deferred_debt else 7.4,
                    "critical",
                    "amm_pair_burn_sync_reserve_desync",
                    fname,
                    lead_only=False,
                    tests=[
                        "Fork PoC: accumulate burn debt through a sell/transfer, trigger the burn path, then compare pair reserves before/after sync().",
                        "Swap after the forced pair burn and verify the paired asset can be drained or mispriced.",
                        "Confirm the burn amount was not deducted from the seller before it was later burned from the pair.",
                    ],
                    extra={
                        "file": path,
                        "deferred_burn_vars": sorted(burn_debt_vars),
                        **pair_ev,
                    },
                ))
        return out


# --------------------------------------------------------------------------- #
# Vault4626 class: totalAssets quotes non-asset leg, redeem transfers it again
# --------------------------------------------------------------------------- #
_NON_ASSET_WORD = re.compile(r"nonAsset|otherAsset|token0|token1|weth|wrapped|quote", re.I)
_QUOTE_OR_TWAP = re.compile(r"quote|twap|getQuoteAtTick|consult|slot0|sqrtPriceX96|OracleLibrary", re.I)
_TOTAL_ASSETS_RETURN = re.compile(r"return[\s\S]{0,900}(nonAsset|otherAsset|token0|token1|weth|quote)", re.I)
_REDEEM_ASSET_CALC = re.compile(r"convertToAssets\s*\(|previewRedeem\s*\(|totalAssets\s*\(", re.I)
_NON_ASSET_TRANSFER = re.compile(
    r"(?:_safeTransfer|safeTransfer|transfer)\s*\(\s*"
    r"(?:[A-Za-z_]\w*)?(?:nonAsset|otherAsset|weth|token0|token1|quote)\w*"
    r"\s*,\s*(?:receiver|recipient|to|owner)\b"
    r"|(?:[A-Za-z_]\w*)?(?:nonAsset|otherAsset|weth|token0|token1|quote)\w*"
    r"\s*\.\s*(?:safeTransfer|transfer)\s*\(\s*(?:receiver|recipient|to|owner)\b",
    re.I,
)


class Erc4626DualAssetRedeemDoubleCountDetector(Detector):
    name = "erc4626_dual_asset_redeem_double_count"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            total_assets_fns: list[str] = []
            function_bodies = list(iter_function_bodies(src))
            for fname, _params, _tail, body in function_bodies:
                if fname != "totalAssets":
                    continue
                if _NON_ASSET_WORD.search(body) and _QUOTE_OR_TWAP.search(body) and _TOTAL_ASSETS_RETURN.search(body):
                    total_assets_fns.append(fname)
            if not total_assets_fns:
                continue

            for fname, _params, tail, body in function_bodies:
                if not re.search(r"redeem|withdraw|exit", fname, re.I):
                    continue
                if re.search(r"\b(view|pure)\b", tail, re.I):
                    continue
                if not (_REDEEM_ASSET_CALC.search(body) and _NON_ASSET_TRANSFER.search(body)):
                    continue
                out.append(_finding(
                    self.name,
                    "erc4626_redeem_double_pays_quoted_non_asset_leg",
                    f"ERC4626 redeem appears to pay a quoted non-asset leg twice: {fname}",
                    (
                        f"`totalAssets()` values a non-asset/LP leg through a quote/TWAP, then "
                        f"`{fname}` calculates redeemable assets from that total and separately "
                        "transfers the non-asset token to the receiver. A redeemer can donate or "
                        "control the non-asset balance, inflate totalAssets, and receive both the "
                        "quoted value and the actual non-asset tokens. This is the Vault4626 "
                        "2026 double-pay redeem class."
                    ),
                    9.2,
                    7.8,
                    "critical",
                    "erc4626_dual_asset_redeem_double_count",
                    fname,
                    lead_only=False,
                    tests=[
                        "Fork/unit PoC: deposit enough underlying to own most shares, donate non-asset token, then redeem and compare paid asset + non-asset value against pro-rata TVL.",
                        "Check whether totalAssets() already includes the same nonAssetToSend value that redeem transfers separately.",
                        "Assert redeem value conservation: assetValuePaid + nonAssetValuePaid <= shares / totalSupplyBefore * totalAssetsBefore.",
                    ],
                    extra={"file": path, "total_assets_function": "totalAssets"},
                ))
        return out
