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


# --------------------------------------------------------------------------- #
# Cross-chain receiver source/peer auth (KelpDAO LayerZero, CCIP)
# --------------------------------------------------------------------------- #
_RECV_RE = re.compile(r"(?:_?lzReceive|nonblockingLzReceive|_?ccipReceive)\b", re.I)
_RECV_CALLER_RE = re.compile(
    r"msg\.sender\s*==\s*(?:address\s*\(\s*)?\w*endpoint|onlyEndpoint|"
    r"require\s*\([^;]*\bendpoint\b|msg\.sender\s*==\s*\w*router", re.I)
_RECV_PEER_RE = re.compile(
    r"trustedRemote|peers?\s*\[|_?getPeerOrRevert|allowlistedSourceChains?\s*\[|"
    r"allowlistedSenders?\s*\[|sourceChainSelector|_assertPeer", re.I)


class CrossChainReceiverSourceAuthDetector(Detector):
    name = "cross_chain_receiver_source_auth"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not _RECV_RE.search(fname):
                    continue
                if _RECV_CALLER_RE.search(body) or _RECV_PEER_RE.search(body):
                    continue
                out.append(FindingCandidate(
                    detector=self.name,
                    title=f"Cross-chain receiver does not bind the source/peer: {fname}",
                    description=(
                        f"`{fname}` is a LayerZero/CCIP message receiver but its body neither "
                        "asserts the caller is the endpoint/router nor binds the origin to a "
                        "configured peer/trusted-remote (peers[srcEid] / sourceChainSelector + "
                        "sender allowlist). A forged packet from an unauthorized source can drive "
                        "the credit/mint/release path (KelpDAO LayerZero class). Confirm the base "
                        "OApp/CCIPReceiver enforces these before trusting."
                    ),
                    impact_score=9.0, confidence_score=5.5, severity_candidate="critical",
                    evidence={"function": fname, "file": path, "snippet": body[:1500],
                              "bug_class": "cross_chain", "needs_poc": True, "unprivileged": True},
                    next_tests=[
                        "Call the receiver from an unauthorized source/peer; confirm funds release",
                        "Verify peers[srcEid]/trusted-remote and endpoint checks exist (here or in the base)",
                    ],
                    affected_functions=[fname]))
        return out


# --------------------------------------------------------------------------- #
# ERC-4626 first-depositor / donation share inflation (Sonne, Hundred)
# --------------------------------------------------------------------------- #
class VaultShareDonationInflationDetector(Detector):
    name = "vault_share_donation_inflation"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        full = ctx.all_source_text()
        has_offset = re.search(
            r"decimalsOffset|_decimalsOffset|virtual\w*[Ss]hare|MINIMUM_LIQUIDITY|"
            r"_mint\s*\(\s*address\s*\(\s*0|_mint\s*\(\s*0x[dD][eE][aA][dD]|deadShares|"
            r"10\s*\*\*\s*_?\w*[Oo]ffset", full)
        has_internal = re.search(
            r"_totalAssets\b|storedAssets|internalBalance|totalManagedAssets|_cash\b|"
            r"_reserve\b|internalCash", full, re.I)
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if not re.search(r"(deposit|mint|convertToShares|previewDeposit|issue)", fname, re.I):
                    continue
                bal = re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", body)
                supply = re.search(r"totalSupply|totalShares", body)
                if bal and supply and re.search(r"[*/]", body) and not has_offset and not has_internal:
                    out.append(FindingCandidate(
                        detector=self.name,
                        title=f"ERC4626-style share price from balanceOf(this), no inflation guard: {fname}",
                        description=(
                            f"`{fname}` derives shares from totalSupply and a totalAssets sourced "
                            "directly from token.balanceOf(address(this)), with no virtual-shares "
                            "offset, dead-shares mint, or internal-accounting variable. A first "
                            "depositor mints 1 wei of shares then DONATES tokens by direct transfer, "
                            "inflating share price so later depositors round to 0 (ERC4626 "
                            "first-depositor inflation; Sonne/Hundred class)."
                        ),
                        impact_score=8.0, confidence_score=6.0, severity_candidate="high",
                        evidence={"function": fname, "file": path, "snippet": body[:1500],
                                  "bug_class": "share_inflation", "needs_poc": True, "unprivileged": True},
                        next_tests=[
                            "Fork PoC: first depositor mints 1 wei, direct-transfers a large amount, victim deposits; confirm victim shares round to 0",
                            "Confirm no virtual-shares offset / dead-shares mint on first deposit",
                        ],
                        affected_functions=[fname]))
                    break
        return out


# --------------------------------------------------------------------------- #
# ERC-2771 _msgSender spoof via self-delegatecall Multicall (thirdweb TIME)
# --------------------------------------------------------------------------- #
class Erc2771MsgSenderSpoofDetector(Detector):
    name = "erc2771_msgsender_spoof"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        full = ctx.all_source_text()
        has_2771 = re.search(
            r"ERC2771Context|isTrustedForwarder|trustedForwarder|"
            r"msg\.data\s*\[\s*msg\.data\.length\s*-\s*20", full, re.I)
        self_dc_multicall = bool(re.search(r"\bmulticall\b", full, re.I)) and bool(
            re.search(r"address\s*\(\s*this\s*\)\s*\.\s*delegatecall|"
                      r"delegatecall\s*\(\s*\w*data\s*\[", full, re.I))
        if not (has_2771 and self_dc_multicall):
            return []
        return [FindingCandidate(
            detector=self.name,
            title="ERC-2771 _msgSender() spoofable via self-delegatecall Multicall",
            description=(
                "This contract uses an ERC-2771 trusted-forwarder _msgSender() AND a "
                "delegatecall-based Multicall. An attacker routes a batch through the forwarder "
                "and appends an arbitrary victim address to each calldata item, so _msgSender() "
                "reads the victim — defeating every _msgSender()-keyed access check (thirdweb TIME "
                "class). Apply OZ _contextSuffixLength() handling or remove the self-delegatecall."
            ),
            impact_score=8.5, confidence_score=6.0, severity_candidate="high",
            evidence={"bug_class": "access_control", "needs_poc": True, "unprivileged": True},
            next_tests=[
                "Via the trusted forwarder, call multicall with calldata suffixed by a victim address; confirm _msgSender() resolves to the victim",
                "Confirm the contract lacks the _contextSuffixLength() multicall fix",
            ],
            affected_functions=["multicall"])]


# --------------------------------------------------------------------------- #
# Unprotected initializer wiring a delegatecall/impl target (Renegade)
# --------------------------------------------------------------------------- #
class ReinitializableProxyDelegatecallDetector(Detector):
    name = "reinitializable_proxy_delegatecall"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            wires_dc = bool(re.search(r"\bdelegatecall\b", src))
            for fname, params, tail, body in iter_function_bodies(src):
                if not re.search(r"initialize|reinitialize|__\w+_init|migrate|setup", fname, re.I):
                    continue
                guarded = re.search(
                    r"\binitializer\b|reinitializer|_disableInitializers|onlyOwner|onlyProxy|"
                    r"require\s*\([^;]*initiali", tail + body, re.I)
                wires = re.search(
                    r"(implementation|_?logic|impl)\w*\s*=\s*\w|_setImplementation|"
                    r"delegatecall|sstore\s*\(\s*_?IMPLEMENTATION", body, re.I)
                if not guarded and wires and wires_dc:
                    out.append(FindingCandidate(
                        detector=self.name,
                        title=f"Unprotected initializer wires a delegatecall/implementation target: {fname}",
                        description=(
                            f"`{fname}` is an initializer/migration with no initializer/onlyOwner "
                            "guard, and it sets an implementation/logic/delegatecall target. Anyone "
                            "can front-run or re-run it to point the proxy at attacker logic, which "
                            "then delegatecalls in the proxy's storage context and sweeps funds "
                            "(Renegade uninitialized-proxy class). Add an initializer guard and "
                            "_disableInitializers() in the implementation constructor."
                        ),
                        impact_score=9.0, confidence_score=6.0, severity_candidate="critical",
                        evidence={"function": fname, "file": path, "snippet": body[:1500],
                                  "bug_class": "proxy", "needs_poc": True, "unprivileged": True},
                        next_tests=[
                            "From an unprivileged EOA call the initializer with attacker addresses; confirm the impl/logic target is set",
                            "Confirm no initializer modifier and no _disableInitializers() in the impl constructor",
                        ],
                        affected_functions=[fname]))
        return out


# --------------------------------------------------------------------------- #
# payable multicall msg.value reuse (SushiSwap MISO, Opyn)
# --------------------------------------------------------------------------- #
class PayableMulticallMsgValueReuseDetector(Detector):
    name = "payable_multicall_msgvalue_reuse"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        out: list[FindingCandidate] = []
        for path, src in ctx.source_files.items():
            if not src:
                continue
            for fname, params, tail, body in iter_function_bodies(src):
                if "payable" not in tail.lower():
                    continue
                if not re.search(r"\bfor\s*\(|\bwhile\s*\(", body):
                    continue
                if re.search(r"address\s*\(\s*this\s*\)\s*\.\s*delegatecall|"
                             r"delegatecall\s*\(\s*\w*\s*\[", body, re.I):
                    out.append(FindingCandidate(
                        detector=self.name,
                        title=f"payable function batches self-delegatecalls (msg.value reuse): {fname}",
                        description=(
                            f"`{fname}` is payable and loops over self-delegatecalls "
                            "(address(this).delegatecall(data[i])). delegatecall preserves "
                            "msg.value, so each batched payable sub-call sees the FULL msg.value "
                            "though ETH arrived once — counting the same value N times (SushiSwap "
                            "MISO / Opyn class). Make the batcher non-payable or account msg.value "
                            "exactly once before the loop."
                        ),
                        impact_score=8.5, confidence_score=6.0, severity_candidate="high",
                        evidence={"function": fname, "file": path, "snippet": body[:1500],
                                  "bug_class": "arithmetic_logic", "needs_poc": True, "unprivileged": True},
                        next_tests=[
                            "Send ETH once to multicall with N sub-calls reading msg.value; confirm N-fold credit",
                            "Confirm there is no single msg.value accounting before the loop",
                        ],
                        affected_functions=[fname]))
        return out
