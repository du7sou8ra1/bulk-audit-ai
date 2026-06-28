"""Elite Phase 9 weird-hunt detectors.

Rare smart-contract bug classes that are easy to miss with single-function regex
rules. These detectors are intentionally conservative: they emit candidates with
concrete evidence and next tests, not confirmed exploit reports. They lean on the
Phase 8 semantic/taint facts when available and fall back to the legacy source
helpers when scans run without a prebuilt context.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .base import Detector, FindingCandidate, TargetContext, header_has_access_control, iter_function_bodies, strip_comments
from ..core.semantic_index import ContractFacts, FunctionFacts, build_semantic_index
from ..core.taint import flows_to_sink


@dataclass
class FnView:
    name: str
    params: str
    tail: str
    body: str
    file: str
    facts: FunctionFacts | None = None


_VALUE_SINK_RE = re.compile(
    r"\.\s*(?:transfer|safeTransfer|transferFrom|safeTransferFrom)\s*\(|\.call\s*\{|_mint\s*\(|mint\s*\(|_burn\s*\(",
    re.I,
)
_GUARD_RE = re.compile(
    r"only[A-Z_]|hasRole\s*\(|requiresAuth|restricted|auth\b|msg\.sender\s*==|_msgSender\s*\(\s*\)\s*==",
    re.I,
)


def _semantic(ctx: TargetContext) -> ContractFacts:
    facts = getattr(ctx, "semantic", None)
    if facts is not None:
        return facts
    return build_semantic_index(ctx.source_files, ctx.abi)


def _iter(ctx: TargetContext) -> Iterable[FnView]:
    facts = getattr(ctx, "semantic", None)
    by_file_line: dict[tuple[str, str], list[FunctionFacts]] = {}
    if facts is not None:
        for fn in facts.functions_by_key.values():
            by_file_line.setdefault((fn.file, fn.name), []).append(fn)
    for path, src in ctx.source_files.items():
        if not src:
            continue
        clean = strip_comments(src)
        for name, params, tail, body in iter_function_bodies(clean):
            fns = by_file_line.get((path, name), [])
            facts_match = fns.pop(0) if fns else None
            yield FnView(name=name, params=params, tail=tail, body=body, file=path, facts=facts_match)


def _param_names(params: str) -> set[str]:
    out: set[str] = set()
    depth = 0
    buf = ""
    parts: list[str] = []
    for ch in params or "":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf)
    for part in parts:
        toks = re.findall(r"[A-Za-z_]\w*", part)
        if toks:
            out.add(toks[-1])
    return out


def _has_guard(fn: FnView) -> bool:
    return header_has_access_control(fn.tail) or bool(_GUARD_RE.search(fn.tail + "\n" + fn.body))


def _has_value_sink(body: str) -> bool:
    return bool(_VALUE_SINK_RE.search(body))


def _body_has_any(body: str, words: Iterable[str]) -> bool:
    return any(re.search(rf"\b{re.escape(w)}\b", body, re.I) for w in words)


def _finding(
    detector: str,
    rule_id: str,
    title: str,
    desc: str,
    impact: float,
    conf: float,
    sev: str,
    bug_class: str,
    fn: FnView,
    *,
    tests: list[str],
    extra: dict | None = None,
    lead_only: bool = True,
) -> FindingCandidate:
    ev = {
        "source": detector,
        "rule_id": rule_id,
        "bug_class": bug_class,
        "file": fn.file,
        "snippet": (fn.tail + "\n" + fn.body)[:2500],
        "rare_lead": True,
        "needs_poc": True,
        "needs_stateful_poc": True,
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
        next_tests=tests,
        affected_functions=[fn.name] if fn.name else [],
    )


class ActualReceivedAccountingDetector(Detector):
    name = "actual_received_accounting"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        fn_name = re.compile(r"deposit|mint|stake|supply|addLiquidity|join", re.I)
        received_guard = re.compile(r"balanceBefore|balanceAfter|received|actualReceived|delta", re.I)
        for fn in _iter(ctx):
            body = fn.body
            if not fn_name.search(fn.name) or not re.search(r"transferFrom|safeTransferFrom", body):
                continue
            if received_guard.search(body):
                continue
            if not re.search(r"_mint\s*\([^;]*\bamount\b|shares\s*=|minted\s*=|balanceOf\s*\(\s*address\s*\(\s*this", body, re.I):
                continue
            out.append(_finding(
                self.name,
                "nominal_amount_used_without_received_delta",
                f"Deposit/share accounting uses nominal amount without received delta: {fn.name}",
                f"`{fn.name}` pulls tokens with transferFrom and mints/accounts from a caller-supplied amount without measuring balanceBefore/balanceAfter. Fee-on-transfer or rebasing tokens can mint too many shares or credits.",
                8.5, 5.0, "high", "actual_received_accounting", fn,
                tests=["Use a fee-on-transfer mock token in a fork/unit test and compare shares minted vs actual received."],
                extra={"economic_leverage": True, "value_sink": True},
            ))
        return out


class MerkleClaimBindingDetector(Detector):
    name = "merkle_claim_binding"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            body = fn.body
            if "MerkleProof" not in body and "merkle" not in body.lower():
                continue
            if "keccak256" not in body or not _has_value_sink(body):
                continue
            leaf_match = re.search(r"leaf\s*=\s*keccak256\s*\((.*?)\)\s*;", body, re.I | re.S)
            leaf = leaf_match.group(1) if leaf_match else body
            required = {
                "recipient": re.compile(r"recipient|account|user|msg\.sender|to\b", re.I),
                "amount": re.compile(r"amount|value|shares|quantity", re.I),
                "token": re.compile(r"token|asset|currency", re.I),
                "index_or_nonce": re.compile(r"index|idx|nonce|id|claimId|chainid|chainId", re.I),
            }
            missing = [name for name, pat in required.items() if not pat.search(leaf)]
            if len(missing) < 2:
                continue
            out.append(_finding(
                self.name,
                "merkle_leaf_missing_value_or_domain_fields",
                f"Merkle claim leaf appears weakly bound: {fn.name}",
                f"`{fn.name}` verifies a Merkle proof and moves value, but the visible leaf preimage appears to omit {', '.join(missing)}. Weak leaves can let a proof be reused for another recipient, amount, token, or claim index.",
                8.5, 5.0, "high", "merkle_claim_binding", fn,
                tests=["Rebuild the leaf off-chain and try the same proof with modified omitted fields in a local test."],
                extra={"binding_fields_missing": missing, "value_sink": True},
            ))
        return out


class BitmapClaimCollisionDetector(Detector):
    name = "bitmap_claim_collision"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"claimed|bitmap|bitMap|claimedBitMap", b, re.I):
                continue
            bad_shift = re.search(r"1\s*<<\s*(?:index|idx|i)\b", b) and not re.search(r"%\s*256|&\s*255", b)
            trunc = re.search(r"uint8\s*\(\s*(?:index|idx|i)\s*\)", b)
            if not (bad_shift or trunc):
                continue
            out.append(_finding(
                self.name, "bitmap_claim_index_collision", f"Claim bitmap can collide or alias indexes: {fn.name}",
                f"`{fn.name}` uses bitmap claim tracking with an unsafe shift/cast pattern. Indexes can alias across words or truncate, enabling double-claim or false-claim states.",
                8.0, 5.5, "high", "bitmap_claim_collision", fn,
                tests=["Unit test two indexes separated by 256 or above uint8 range and confirm both map to the same claimed bit."],
                extra={"value_sink": _has_value_sink(b)}, lead_only=False,
            ))
        return out


class BridgeReplayKeyDetector(Detector):
    name = "bridge_replay_key"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        bridge_fn = re.compile(r"receive|relay|execute|finalize|bridge|message|packet|lzReceive|ccipReceive", re.I)
        domain = re.compile(r"src|source|sender|peer|remote|chain|domain|eid|selector|nonce|messageId|packetId|block\.chainid|address\s*\(\s*this", re.I)
        for fn in _iter(ctx):
            b = fn.body
            if not bridge_fn.search(fn.name + " " + b) or not re.search(r"processed|consumed|executed|used", b, re.I):
                continue
            if not _has_value_sink(b):
                continue
            hm = re.search(r"keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\((.*?)\)\s*\)", b, re.I | re.S)
            if not hm:
                continue
            args = hm.group(1)
            anchors = set(m.group(0).lower() for m in domain.finditer(args))
            if len(anchors) >= 4:
                continue
            out.append(_finding(
                self.name, "bridge_message_key_missing_domain_fields", f"Bridge replay key misses domain/provenance fields: {fn.name}",
                f"`{fn.name}` marks a bridge message processed and moves value, but the replay key does not visibly bind source chain, sender/peer, nonce/message id, and destination domain together.",
                9.0, 5.0, "critical", "bridge_replay_key", fn,
                tests=["Try replaying the same payload under a modified source chain/sender/nonce on a fork or unit harness."],
                extra={"hash_args": args[:400], "economic_leverage": True, "value_sink": True},
            ))
        return out


class AddressAliasBridgeDetector(Detector):
    name = "address_alias_bridge"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            text = fn.tail + "\n" + fn.body
            if not re.search(r"xDomain|crossDomain|L1|L2|Optimism|Arbitrum|messenger|bridge", text, re.I):
                continue
            if not re.search(r"msg\.sender|xDomainMessageSender|crossDomainMessageSender", text):
                continue
            if re.search(r"AddressAliasHelper|undoL1ToL2Alias|applyL1ToL2Alias|wasMyCallersAddressAliased", text):
                continue
            if not (_has_value_sink(fn.body) or re.search(r"execute|finalize|mint|unlock", text, re.I)):
                continue
            out.append(_finding(
                self.name, "cross_domain_sender_alias_not_normalized", f"Cross-domain sender check may miss address aliasing: {fn.name}",
                f"`{fn.name}` trusts a cross-domain sender/caller but no L1<->L2 address alias normalization is visible. Alias mismatch can authorize the wrong bridge peer on rollups.",
                8.0, 4.5, "high", "address_alias_bridge", fn,
                tests=["Check the target chain's alias rules and fork-test the aliased and unaliased sender values."],
            ))
        return out


class OracleFreshnessSequencerDetector(Detector):
    name = "oracle_freshness_sequencer"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        l2 = (ctx.chain or "").lower() in {"arbitrum", "optimism", "base", "polygon", "scroll", "linea", "zksync", "blast"}
        for fn in _iter(ctx):
            b = fn.body
            if "latestRoundData" not in b:
                continue
            missing = []
            if not re.search(r"updatedAt\s*>|block\.timestamp\s*-\s*updatedAt|stale|heartbeat", b, re.I):
                missing.append("updatedAt/stale check")
            if not re.search(r"answeredInRound\s*>=\s*roundId|roundId\s*<=\s*answeredInRound", b):
                missing.append("answeredInRound check")
            if not re.search(r"answer\s*>\s*0|price\s*>\s*0", b):
                missing.append("positive answer check")
            if l2 and not re.search(r"sequencer|gracePeriod|uptime", b, re.I):
                missing.append("L2 sequencer uptime check")
            if not missing or not re.search(r"borrow|mint|withdraw|liquidat|swap|collateral|value|price", fn.name + b, re.I):
                continue
            out.append(_finding(
                self.name, "chainlink_oracle_missing_freshness_or_sequencer_check", f"Oracle price used without full freshness checks: {fn.name}",
                f"`{fn.name}` reads Chainlink `latestRoundData()` for value logic but appears to miss {', '.join(missing)}.",
                8.0, 5.5, "high", "oracle_freshness_sequencer", fn,
                tests=["Fork/unit test stale, zero/negative, and L2 sequencer-down oracle responses against borrow/mint/withdraw/liquidation paths."],
                extra={"missing_checks": missing, "economic_leverage": True}, lead_only=False,
            ))
        return out


class TwapObservationCardinalityDetector(Detector):
    name = "twap_observation_cardinality"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"observe\s*\(|consult\s*\(|slot0\s*\(|secondsAgo|twap", b, re.I):
                continue
            weak_period = re.search(r"secondsAgo\s*=\s*0|period\s*=\s*0|secondsAgo\s*\[\s*0\s*\]\s*=\s*0", b, re.I) or (
                "period" in _param_names(fn.params) and not re.search(r"require\s*\([^)]*period\s*>=|MIN_TWAP|minimum", b, re.I)
            )
            no_cardinality = not re.search(r"observationCardinality|increaseObservationCardinalityNext|cardinality", b, re.I)
            if not (weak_period and no_cardinality):
                continue
            out.append(_finding(
                self.name, "twap_can_degrade_to_spot_or_low_cardinality", f"TWAP can degrade to spot or low-cardinality oracle: {fn.name}",
                f"`{fn.name}` uses TWAP/observe/slot0 logic without a visible minimum period and observation-cardinality guard.",
                7.5, 4.5, "high", "twap_observation_cardinality", fn,
                tests=["Fork a low-liquidity pool, set period=0 or too short, and confirm price can be manipulated in one block."],
                extra={"economic_leverage": True},
            ))
        return out


class ForcedEthAccountingDetector(Detector):
    name = "forced_eth_accounting"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if "address(this).balance" not in b:
                continue
            if not re.search(r"share|totalAssets|price|solvency|reward|mint|withdraw|redeem|claim", fn.name + b, re.I):
                continue
            if re.search(r"accountedBalance|internalBalance|trackedBalance|totalManagedAssets|asset\.balanceOf", b, re.I):
                continue
            out.append(_finding(
                self.name, "native_balance_used_as_accounting", f"address(this).balance used as protocol accounting: {fn.name}",
                f"`{fn.name}` uses `address(this).balance` in share/reward/solvency math. Forced ETH via selfdestruct or coinbase payments can skew accounting.",
                7.5, 5.0, "high", "forced_eth_accounting", fn,
                tests=["On a local fork, force ETH into the contract with selfdestruct and compare share price/reward/withdraw output before and after."],
                extra={"economic_leverage": True}, lead_only=False,
            ))
        return out


class Create2MetamorphicTrustDetector(Detector):
    name = "create2_metamorphic_trust"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"CREATE2|create2|salt|extcodesize|codehash|isContract|\.code\.length", b):
                continue
            if not re.search(r"allow|trust|whitelist|implementation|module|adapter|strategy|target", fn.name + b, re.I):
                continue
            if re.search(r"initCodeHash|runtimeCodeHash|expectedCodeHash|immutable|deployedBytecode", b, re.I):
                continue
            out.append(_finding(
                self.name, "address_only_trust_create2_or_code_check", f"Address-only trust around CREATE2/code check: {fn.name}",
                f"`{fn.name}` appears to trust an address/code-existence check around CREATE2 or extcodesize without binding the expected runtime code hash. Metamorphic or not-yet-deployed contracts can bypass address-only trust.",
                8.0, 4.0, "high", "create2_metamorphic_trust", fn,
                tests=["Unit test allowlisting/checking before deployment, then deploy different code to the same CREATE2 address if the factory permits it."],
            ))
        return out


class TryCatchFinalizationDetector(Detector):
    name = "trycatch_finalization"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"try\s+[^{}]+\{", b) or "catch" not in b:
                continue
            consumed_pos = _first_pos(b, r"(processed|consumed|executed|claimed|used)\s*\[[^\]]+\]\s*=")
            try_pos = _first_pos(b, r"try\s+")
            catch = re.search(r"catch\s*(?:\([^)]*\))?\s*\{(?P<body>.*?)\}", b, re.I | re.S)
            swallows = bool(catch and not re.search(r"revert|throw|return\s+false", catch.group("body"), re.I))
            if consumed_pos == -1 or try_pos == -1 or consumed_pos > try_pos or not swallows:
                continue
            out.append(_finding(
                self.name, "message_consumed_before_trycatch_swallow", f"Message finalized even when execution fails: {fn.name}",
                f"`{fn.name}` marks a message/claim consumed before a `try/catch`, and the catch block appears to swallow failure. Failed execution can become non-retryable, locking or losing funds/messages.",
                8.0, 5.0, "high", "trycatch_finalization", fn,
                tests=["Make the external call revert in a local test and confirm the processed/consumed marker remains set."],
                extra={"cross_function": True}, lead_only=False,
            ))
        return out


class RewardDebtOrderDetector(Detector):
    name = "reward_debt_order"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"claim|harvest|getReward|withdraw", fn.name, re.I):
                continue
            transfer_pos = _first_pos(b, r"\.\s*(safeTransfer|transfer|call)\s*(?:\(|\{)")
            debt_pos = _first_pos(b, r"(rewardDebt|lastClaim|claimed|checkpoint|userIndex)\s*(?:\[[^\]]+\])?\s*=")
            if transfer_pos == -1 or debt_pos == -1 or transfer_pos > debt_pos:
                continue
            if re.search(r"nonReentrant|ReentrancyGuard", fn.tail + b, re.I):
                continue
            out.append(_finding(
                self.name, "reward_transferred_before_debt_update", f"Reward transfer happens before debt/checkpoint update: {fn.name}",
                f"`{fn.name}` transfers reward value before updating rewardDebt/claimed/checkpoint state. Token hooks or receiver callbacks may reenter and double-claim.",
                8.5, 5.5, "high", "reward_debt_order", fn,
                tests=["Use a malicious reward token/receiver hook to reenter claim before rewardDebt is updated."],
                extra={"economic_leverage": True, "value_sink": True}, lead_only=False,
            ))
        return out


class AccumulatorZeroSupplyDetector(Detector):
    name = "accumulator_zero_supply"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"acc\w*Per\w+|rewardPerShare|index\s*\+=|globalIndex", b, re.I):
                continue
            if not re.search(r"/\s*(?:totalSupply|totalShares|supply|shares)\b", b):
                continue
            if re.search(r"(?:totalSupply|totalShares|supply|shares)\s*==\s*0|>\s*0|!=\s*0", b):
                continue
            out.append(_finding(
                self.name, "reward_accumulator_divides_by_zero_supply", f"Reward accumulator updates without zero-supply branch: {fn.name}",
                f"`{fn.name}` updates an accumulator by dividing rewards over total supply/shares without a visible zero-supply branch. Rewards can be lost, stuck, or overallocated around empty-pool transitions.",
                7.0, 5.0, "high", "accumulator_zero_supply", fn,
                tests=["Unit test reward injection when supply is zero, then first deposit/claim after supply becomes nonzero."],
                extra={"economic_leverage": True}, lead_only=False,
            ))
        return out


class PositionMergeSplitDetector(Detector):
    name = "position_merge_split"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"split|merge|migrate|transferPosition|combine", fn.name, re.I):
                continue
            if not re.search(r"position|tokenId|ownerOf|_mint|_burn|ERC721", b, re.I):
                continue
            clears_source = re.search(r"delete\s+\w+\s*\[|=\s*0|_burn\s*\(", b, re.I)
            if clears_source and re.search(r"rewardDebt|collateral|debt|checkpoint", b, re.I):
                continue
            if not re.search(r"collateral|debt|reward|checkpoint|liquidity|shares", b, re.I):
                continue
            out.append(_finding(
                self.name, "position_split_merge_may_duplicate_state", f"Position split/merge may duplicate collateral/reward/debt state: {fn.name}",
                f"`{fn.name}` changes ERC721/position ownership while touching collateral/debt/reward-like state, but no clear source-position cleanup is visible.",
                8.0, 4.5, "high", "position_merge_split", fn,
                tests=["Create a position with accrued debt/rewards, split/merge it, then check source and destination totals/invariants."],
                extra={"cross_function": True},
            ))
        return out


class GovernanceSnapshotBypassDetector(Detector):
    name = "governance_snapshot_bypass"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"vote|quorum|proposal|execute", fn.name + b, re.I):
                continue
            if not re.search(r"balanceOf\s*\(|totalSupply\s*\(|getVotes\s*\(", b):
                continue
            if re.search(r"proposalSnapshot|getPastVotes|getPriorVotes|checkpoint|snapshotBlock|blockNumber", b, re.I):
                continue
            out.append(_finding(
                self.name, "governance_uses_current_balance_without_snapshot", f"Governance power appears current-balance based: {fn.name}",
                f"`{fn.name}` uses current balances/votes for proposal or quorum logic without a visible snapshot/checkpoint block. Flash-loaned or same-block voting power can bypass governance assumptions.",
                8.0, 4.5, "high", "governance_snapshot_bypass", fn,
                tests=["Fork/unit test borrowing/transferring voting power in the same block/transaction as vote or execute."],
                extra={"economic_leverage": True},
            ))
        return out


class PausabilityBypassDetector(Detector):
    name = "pausability_bypass"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        facts = _semantic(ctx)
        guarded_internal: set[str] = set()
        unguarded_alt: list[FnView] = []
        for fn in _iter(ctx):
            if re.search(r"whenNotPaused|notPaused|paused\s*\(\s*\)", fn.tail + fn.body, re.I):
                guarded_internal.update(getattr(fn.facts, "calls", set()) if fn.facts else set())
            if re.search(r"multicall|callback|claim|emergency|execute|permitAndCall|batch", fn.name, re.I) and not re.search(r"whenNotPaused|notPaused|paused", fn.tail + fn.body, re.I):
                unguarded_alt.append(fn)
        out = []
        if not guarded_internal:
            return out
        for fn in unguarded_alt:
            calls = getattr(fn.facts, "calls", set()) if fn.facts else set()
            overlap = sorted(calls & guarded_internal)
            if not overlap and not _has_value_sink(fn.body):
                continue
            out.append(_finding(
                self.name, "alternate_entrypoint_reaches_paused_sink", f"Alternate entrypoint may bypass pause: {fn.name}",
                f"`{fn.name}` is an alternate entrypoint without a visible pause guard and reaches value-moving/internal logic also used by paused paths.",
                7.5, 4.5, "high", "pausability_bypass", fn,
                tests=["Pause the protocol in a unit/fork test, then call the alternate entrypoint and confirm the same state/value sink remains reachable."],
                extra={"shared_internal_calls": overlap, "cross_function": True},
            ))
        return out


class MulticallStateCacheDetector(Detector):
    name = "multicall_state_cache"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            if not re.search(r"multicall|batch", fn.name, re.I) and "delegatecall" not in b:
                continue
            if "delegatecall" not in b or not re.search(r"payable|msg\.value|balanceBefore|cached|remainingValue", fn.tail + b, re.I):
                continue
            if re.search(r"valueUsed|msgValueRemaining|consumeValue|spentValue", b, re.I):
                continue
            out.append(_finding(
                self.name, "payable_multicall_reuses_msg_value_or_cached_state", f"Payable multicall/delegatecall may reuse msg.value or cached state: {fn.name}",
                f"`{fn.name}` delegatecalls batched calldata in a payable/value-cached context without visible consumed-value accounting. Inner calls may reuse `msg.value` or stale cached balances.",
                8.5, 5.0, "high", "multicall_state_cache", fn,
                tests=["Call the same payable deposit/mint function twice through multicall with one msg.value and compare credited value."],
                extra={"economic_leverage": True, "cross_function": True}, lead_only=False,
            ))
        return out


class WadRayUnitMismatchDetector(Detector):
    name = "wad_ray_unit_mismatch"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            b = fn.body
            constants = set(re.findall(r"\b(?:WAD|RAY|BPS|1e18|1e27|1e6|10\s*\*\*\s*(?:6|18|27))\b", b))
            if len(constants) < 2:
                continue
            if not re.search(r"\*|/|mulDiv|wmul|wdiv|rayMul|rayDiv", b):
                continue
            if re.search(r"decimals\s*\(|scale|normalize|toWad|toRay|bps", b, re.I):
                continue
            out.append(_finding(
                self.name, "mixed_fixed_point_units_without_normalization", f"Mixed WAD/RAY/token units without visible normalization: {fn.name}",
                f"`{fn.name}` mixes fixed-point constants {', '.join(sorted(constants))} in value math without a visible decimals/normalization step.",
                7.5, 4.5, "high", "wad_ray_unit_mismatch", fn,
                tests=["Unit test tokens with 6/18 decimals and compare formula output against a high-precision reference model."],
                extra={"constants": sorted(constants), "economic_leverage": True},
            ))
        return out


class DuplicateBatchItemDetector(Detector):
    name = "duplicate_batch_item"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out = []
        for fn in _iter(ctx):
            arrays = {p for p in _param_names(fn.params) if re.search(rf"\b\w+\s*\[\]\s*(?:calldata|memory)?\s+{re.escape(p)}\b", fn.params)}
            b = fn.body
            if not arrays or not re.search(r"for\s*\(", b):
                continue
            if re.search(r"seen\s*\[|visited\s*\[|duplicate|unique|dedup|require\s*\([^)]*!\s*seen", b, re.I):
                continue
            if not re.search(r"\+=|transfer|safeTransfer|_mint|_burn|collateral|debt|amount", b, re.I):
                continue
            used = [a for a in arrays if re.search(rf"\b{re.escape(a)}\s*\[\s*(?:i|j|k|idx)\s*\]", b)]
            if not used:
                continue
            out.append(_finding(
                self.name, "batch_loop_no_duplicate_item_guard", f"Batch loop has no duplicate-item guard: {fn.name}",
                f"`{fn.name}` loops over batch array(s) {', '.join(used)} and mutates/transfers value without a visible uniqueness guard. Duplicate ids/items may be double-counted.",
                7.5, 5.0, "high", "duplicate_batch_item", fn,
                tests=["Call the batch function with the same id/token/message twice and compare resulting balance/debt/collateral totals."],
                extra={"array_params": used, "economic_leverage": True}, lead_only=False,
            ))
        return out


class WeirdHuntTaintValueFlowDetector(Detector):
    """Glue detector: exposes Phase 8 high-confidence taint flows as leads."""

    name = "weird_hunt_taint_value_flow"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        facts = _semantic(ctx)
        out: list[FindingCandidate] = []
        for flow in flows_to_sink(facts, source="calldata", sink="value_transfer", min_confidence=0.75):
            if not flow.cross_function:
                continue
            fn = FnView(flow.function, "", "", "", flow.evidence.get("file", ""), facts.get_function(flow.function))
            out.append(_finding(
                self.name, "calldata_cross_function_value_sink", f"Caller-controlled data reaches internal value sink: {flow.entrypoint} -> {flow.function}",
                f"Caller-controlled `{flow.source}` from `{flow.entrypoint}` reaches a value-transfer sink `{flow.sink}` in `{flow.function}` through path {' -> '.join(flow.path)}.",
                8.0, 4.0, "high", "cross_function_value_flow", fn,
                tests=["Write a focused invariant/fork harness that mutates the calldata field and checks whether transferred value/destination changes."],
                extra={"cross_function": True, "value_sink": True, "taint_flow": flow.__dict__},
            ))
        return out[:5]


def _first_pos(body: str, pattern: str) -> int:
    m = re.search(pattern, body, re.I | re.S)
    return m.start() if m else -1
