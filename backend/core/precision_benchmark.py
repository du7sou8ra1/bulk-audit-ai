"""Precision (false-positive) regression benchmark.

``exploit_benchmark.py`` proves RECALL — known-exploited contracts still fire the
expected detectors. This module proves the other half, PRECISION: on known-safe or
misattributed targets the deterministic pipeline must produce ZERO reportable
findings. It operationalizes the batch-130 audit (a real Base scan whose 48 OPEN
findings were 100% false positives) into a permanent gate.

The offline runner mirrors the scanner's DETERMINISTIC filtering only:

    detectors -> mark_corroboration -> dedup -> candidate_sanity -> score_finding

It does NOT invoke the AI refuter, which can only *downgrade*. So a reportable
survivor here is a genuine deterministic false positive — not one that merely
slips past the model. Passing offline is a conservative lower bound on precision.

For LIVE precision measurement against real deployed addresses (the actual value on
a VPS with RPC + Etherscan keys), load a corpus with ``load_precision_corpus`` and
scan those addresses through the normal pipeline; any address labelled ``safe`` /
``not_deployed`` that yields a reportable finding is a precision regression.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from ..models import Classification

REPORTABLE = {
    Classification.CONFIRMED_CRITICAL,
    Classification.LIKELY_CRITICAL_NEEDS_POC,
}


@dataclass(frozen=True)
class PrecisionCase:
    """A target that MUST NOT produce a reportable finding."""
    id: str
    name: str
    chain: str
    reason: str
    source: str = ""          # inline Solidity for the offline runner
    address: str = ""         # on-chain address for live runs
    allow_reportable: bool = False  # True = known gap tracked, not a hard fail


@dataclass
class PrecisionResult:
    case_id: str
    name: str
    passed: bool
    reportable_findings: list[dict] = field(default_factory=list)
    suppressed_count: int = 0
    total_candidates: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Negative corpus — safe / benign patterns that must stay silent. Seeded from
# the batch-130 audit root cause #2 (cross-file / upstream auth not resolved)
# and the IDEAS.md FP-reduction list. Each is a REGRESSION LOCK for a fix.
# ---------------------------------------------------------------------------
PRECISION_NEGATIVE_CASES: tuple[PrecisionCase, ...] = (
    PrecisionCase(
        id="oz_onlyowner_mint",
        name="Standard onlyOwner-guarded ERC20 mint",
        chain="ethereum",
        reason="mint() is guarded by a standard onlyOwner modifier; not an access-control bug.",
        source="""pragma solidity ^0.8.0;
contract Token {
  address public owner;
  mapping(address => uint256) public balanceOf;
  uint256 public totalSupply;
  modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
  constructor() { owner = msg.sender; }
  function mint(address to, uint256 amt) external onlyOwner { balanceOf[to] += amt; totalSupply += amt; }
  function transfer(address to, uint256 amt) external { balanceOf[msg.sender] -= amt; balanceOf[to] += amt; }
}""",
    ),
    PrecisionCase(
        id="custom_guard_bridge_mint",
        name="mint/burn guarded by a custom onlyBridge modifier",
        chain="ethereum",
        reason="mint/burn are guarded by a project-specific modifier whose body checks msg.sender == bridge (IDEAS #1).",
        source="""pragma solidity ^0.8.0;
contract BridgedToken {
  address public bridge;
  mapping(address => uint256) public balanceOf;
  modifier onlyBridge() { require(msg.sender == bridge, "only bridge"); _; }
  function mint(address to, uint256 amt) external onlyBridge { balanceOf[to] += amt; }
  function burn(address from, uint256 amt) external onlyBridge { balanceOf[from] -= amt; }
}""",
    ),
    PrecisionCase(
        id="admin_set_delegatecall",
        name="Proxy delegateTo whose impl is set only by an admin",
        chain="ethereum",
        reason="delegatecall target (implementation) is written only by an onlyAdmin setter, not an attacker (IDEAS #3).",
        source="""pragma solidity ^0.8.0;
contract Delegator {
  address public implementation;
  address public admin;
  modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }
  constructor() { admin = msg.sender; }
  function setImplementation(address impl) external onlyAdmin { implementation = impl; }
  function _delegate() internal { (bool ok, ) = implementation.delegatecall(msg.data); require(ok); }
  fallback() external payable { _delegate(); }
}""",
    ),
    PrecisionCase(
        id="comptroller_verify_non_zk",
        name="Comptroller *Allowed/*Verify hooks with no ZK context",
        chain="ethereum",
        reason="mintAllowed/seizeVerify are comptroller policy callbacks with no verifier/proof/pairing; zk_verifier must not fire (IDEAS #2).",
        source="""pragma solidity ^0.8.0;
contract Comptroller {
  mapping(address => bool) public markets;
  function mintAllowed(address cToken, address minter, uint256 mintAmount) external view returns (uint256) {
    require(markets[cToken], "market not listed");
    return 0;
  }
  function seizeVerify(address cToken, address src, address dst, uint256 seizeTokens) external view {
    require(markets[cToken], "market not listed");
  }
}""",
    ),
    # --- batch-130 root-cause-#2 guard forms (verified already-handled; locked in
    #     as regression cases so the recognizers can never silently regress) ------
    PrecisionCase(
        id="solady_requires_auth",
        name="Solady Auth requiresAuth modifier",
        chain="ethereum",
        reason="mint carries Solady's requiresAuth modifier (body: isAuthorized(msg.sender, msg.sig)); a resolved custom guard.",
        source="""pragma solidity ^0.8.0;
abstract contract Auth {
  address public owner;
  function isAuthorized(address user, bytes4 sig) internal view virtual returns (bool);
  modifier requiresAuth() { require(isAuthorized(msg.sender, msg.sig), "UNAUTHORIZED"); _; }
}
contract Vault is Auth {
  mapping(address => uint256) public balanceOf;
  function isAuthorized(address u, bytes4) internal view override returns (bool) { return u == owner; }
  function mint(address to, uint256 a) external requiresAuth { balanceOf[to] += a; }
}""",
    ),
    PrecisionCase(
        id="oz_access_managed_restricted",
        name="OZ AccessManaged restricted modifier",
        chain="ethereum",
        reason="mint carries OZ AccessManaged's restricted() modifier (delegates to _checkCanCall); a resolved custom guard.",
        source="""pragma solidity ^0.8.0;
abstract contract AccessManaged {
  function _checkCanCall(address caller, bytes calldata data) internal virtual;
  modifier restricted() { _checkCanCall(msg.sender, msg.data); _; }
}
contract Tok is AccessManaged {
  mapping(address => uint256) public balanceOf;
  function _checkCanCall(address, bytes calldata) internal override {}
  function mint(address to, uint256 a) external restricted { balanceOf[to] += a; }
}""",
    ),
    PrecisionCase(
        id="maker_wards_auth",
        name="MakerDAO wards/auth modifier",
        chain="ethereum",
        reason="mint carries Maker's auth modifier (require(wards[msg.sender] == 1)); a resolved custom guard.",
        source="""pragma solidity ^0.8.0;
contract Vat {
  mapping(address => uint256) public wards;
  mapping(address => uint256) public balanceOf;
  modifier auth() { require(wards[msg.sender] == 1, "Vat/not-authorized"); _; }
  function mint(address usr, uint256 wad) external auth { balanceOf[usr] += wad; }
}""",
    ),
    PrecisionCase(
        id="bridge_finalize_only_other_bridge_inline",
        name="Bridge finalize guarded by an inline msg.sender == OTHER_BRIDGE check",
        chain="base",
        reason="finalize/mint is gated by an inline require(msg.sender == OTHER_BRIDGE); an upstream bridge caller-check, not an unauthorized mint.",
        source="""pragma solidity ^0.8.0;
contract L2StandardBridge {
  address public immutable OTHER_BRIDGE;
  mapping(address => uint256) public balanceOf;
  function finalizeBridgeERC20(address to, uint256 amount) external {
    require(msg.sender == OTHER_BRIDGE, "not other bridge");
    balanceOf[to] += amount;
  }
}""",
    ),
    PrecisionCase(
        id="hyperlane_only_mailbox_inline",
        name="Message handler guarded by an inline msg.sender == mailbox check",
        chain="ethereum",
        reason="handle() is gated by an inline require(msg.sender == mailbox); a Hyperlane onlyMailbox upstream caller-check.",
        source="""pragma solidity ^0.8.0;
contract Router {
  address public mailbox;
  mapping(address => uint256) public balanceOf;
  function handle(uint32 origin, bytes32 sender, address to, uint256 amount) external {
    require(msg.sender == mailbox, "!mailbox");
    balanceOf[to] += amount;
  }
}""",
    ),
    PrecisionCase(
        id="whitelist_bitmap_claim",
        name="Merkle airdrop claim with a bit-packed claimedBitMap nullifier",
        chain="ethereum",
        reason="claim() marks a bit-packed claimedBitMap before paying; whitelist_claim_replay must recognize the bitmap replay marker.",
        source="""pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
library MerkleProof { function verify(bytes32[] calldata, bytes32, bytes32) internal pure returns (bool) { return true; } }
contract Airdrop {
  bytes32 public root;
  IERC20 public token;
  mapping(uint256 => uint256) private claimedBitMap;
  function isClaimed(uint256 index) public view returns (bool) {
    uint256 w = index / 256; uint256 b = index % 256;
    return (claimedBitMap[w] & (1 << b)) != 0;
  }
  function _setClaimed(uint256 index) private {
    uint256 w = index / 256; uint256 b = index % 256;
    claimedBitMap[w] |= (1 << b);
  }
  function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external {
    require(!isClaimed(index), "claimed");
    require(MerkleProof.verify(proof, root, keccak256(abi.encodePacked(index, account, amount))), "bad proof");
    _setClaimed(index);
    token.transfer(account, amount);
  }
}""",
    ),
    # --- standard-safe patterns (verified clean) locked in so precision on the
    #     major detectors (oracle / 4626 / signature / access-control) can't regress
    PrecisionCase(
        id="chainlink_consumer_with_staleness",
        name="Chainlink consumer WITH staleness/round/positivity checks",
        chain="ethereum",
        reason="latestRoundData is guarded by ans>0 + updatedAt freshness + answeredInRound; oracle detectors must stay silent.",
        source="""pragma solidity ^0.8.0;
interface AggregatorV3 { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract Oracle {
  AggregatorV3 feed;
  function getPrice() public view returns (uint256) {
    (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
    require(answer > 0, "price");
    require(updatedAt > block.timestamp - 3600, "stale");
    require(answeredInRound >= roundId, "round");
    return uint256(answer);
  }
}""",
    ),
    PrecisionCase(
        id="erc4626_virtual_offset",
        name="ERC-4626 vault with a non-zero virtual/decimals offset",
        chain="ethereum",
        reason="convertToShares uses a non-zero _decimalsOffset() and +1 on totalAssets (OZ virtual-shares); first-depositor inflation is mitigated.",
        source="""pragma solidity ^0.8.0;
contract Vault {
  function totalSupply() public view returns (uint256) {}
  function totalAssets() public view returns (uint256) {}
  function _decimalsOffset() internal view returns (uint8) { return 6; }
  function convertToShares(uint256 assets) public view returns (uint256) {
    return assets * (totalSupply() + 10 ** _decimalsOffset()) / (totalAssets() + 1);
  }
  function deposit(uint256 assets, address r) external returns (uint256 sh) { sh = convertToShares(assets); _mint(r, sh); }
  function _mint(address, uint256) internal {}
}""",
    ),
    PrecisionCase(
        id="erc2612_permit_recompute_guard",
        name="EIP-2612 permit with nonce, deadline, zero-check, and chainid recompute",
        chain="ethereum",
        reason="permit binds nonce+deadline, checks rec != 0 && rec == owner, and rebuilds the domain separator when chainid changes; no replay/zero-addr/cross-fork bug.",
        source="""pragma solidity ^0.8.0;
contract Token {
  mapping(address => uint256) public nonces;
  bytes32 public immutable DOMAIN_SEPARATOR;
  uint256 private immutable _CACHED_CHAIN_ID;
  constructor() { _CACHED_CHAIN_ID = block.chainid; DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this))); }
  function _domainSep() internal view returns (bytes32) {
    return block.chainid == _CACHED_CHAIN_ID ? DOMAIN_SEPARATOR : keccak256(abi.encode(block.chainid, address(this)));
  }
  function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(block.timestamp <= deadline, "expired");
    bytes32 digest = keccak256(abi.encodePacked(hex"1901", _domainSep(),
      keccak256(abi.encode(owner, spender, value, nonces[owner]++, deadline))));
    address rec = ecrecover(digest, v, r, s);
    require(rec != address(0) && rec == owner, "sig");
  }
}""",
    ),
    PrecisionCase(
        id="ownable2step",
        name="OpenZeppelin Ownable2Step transfer/accept flow",
        chain="ethereum",
        reason="transferOwnership is onlyOwner and only sets pendingOwner; acceptOwnership requires msg.sender == pendingOwner. Standard two-step ownership.",
        source="""pragma solidity ^0.8.0;
contract Owned {
  address public owner;
  address public pendingOwner;
  modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
  function transferOwnership(address n) external onlyOwner { pendingOwner = n; }
  function acceptOwnership() external { require(msg.sender == pendingOwner, "not pending"); owner = pendingOwner; pendingOwner = address(0); }
}""",
    ),
    PrecisionCase(
        id="uniswap_v2_pair_factory_init",
        name="Uniswap-V2-style pair with a factory-gated one-time initialize",
        chain="ethereum",
        reason="initialize is gated by msg.sender == factory; getReserves is a plain view; standard AMM pair, not an unprotected initializer or spot-oracle sink.",
        source="""pragma solidity ^0.8.0;
contract Pair {
  uint112 private reserve0;
  uint112 private reserve1;
  address public factory;
  address public token0;
  address public token1;
  function getReserves() public view returns (uint112, uint112) { return (reserve0, reserve1); }
  function initialize(address t0, address t1) external { require(msg.sender == factory, "FORBIDDEN"); token0 = t0; token1 = t1; }
  function swap(uint256 a0, uint256 a1, address to) external { require(a0 > 0 || a1 > 0, "INSUFFICIENT_OUTPUT"); }
}""",
    ),
)


def _build_ctx(case: PrecisionCase, profile: str):
    from ..detectors.base import TargetContext
    from .onchain import OnchainClient
    from .proxy_resolver import ProxyInfo

    ctx = TargetContext(
        address=case.address or "0x0000000000000000000000000000000000000001",
        chain=case.chain,
        profile=profile,
        onchain=OnchainClient(rpc_url=""),
        proxy_info=ProxyInfo(),
        workspace=Path("."),
        contract_name=case.name,
        source_files={f"{case.id}.sol": case.source},
    )
    # Best-effort enrichment (same as the exploit-regression harness).
    try:
        from .semantic_index import build_semantic_index
        from .taint import analyze_taint
        from .protocol_graph import build_protocol_graph

        ctx.semantic = build_semantic_index(ctx.source_files, ctx.abi)
        ctx.taint = analyze_taint(ctx.semantic)
        ctx.protocol_graph = build_protocol_graph(ctx)
    except Exception:
        pass
    return ctx


def run_precision_case(case: PrecisionCase, *, profile: str = "ultra-deep-v2") -> PrecisionResult:
    from . import dedup
    from .candidate_sanity import apply_candidate_sanity
    from .scoring import mark_corroboration, score_finding
    from ..detectors.registry import get_detectors

    result = PrecisionResult(case_id=case.id, name=case.name, passed=False)
    ctx = _build_ctx(case, profile)

    candidates: list = []
    for det in get_detectors(profile):
        try:
            candidates.extend(det.run(ctx))
        except Exception as exc:  # pragma: no cover - reported in result
            result.errors.append(f"{det.name}: {exc}")
    result.total_candidates = len(candidates)

    mark_corroboration(candidates)
    candidates = dedup.collapse_duplicates(candidates)
    result.suppressed_count = apply_candidate_sanity(ctx, candidates)

    for cand in candidates:
        if (cand.evidence or {}).get("suppressed"):
            continue
        try:
            score = score_finding(cand, [], profile=profile)
        except Exception as exc:  # pragma: no cover - reported in result
            result.errors.append(f"score {cand.detector}: {exc}")
            continue
        if score.classification in REPORTABLE:
            result.reportable_findings.append({
                "detector": cand.detector,
                "title": (cand.title or "")[:140],
                "classification": score.classification,
                "impact": round(score.impact_score, 1),
                "confidence": round(score.confidence_score, 1),
                "rule_id": (cand.evidence or {}).get("rule_id"),
            })

    result.passed = case.allow_reportable or not result.reportable_findings
    return result


def run_precision_cases(
    cases: Iterable[PrecisionCase] | None = None, *, profile: str = "ultra-deep-v2"
) -> list[PrecisionResult]:
    return [run_precision_case(c, profile=profile) for c in (cases or PRECISION_NEGATIVE_CASES)]


def precision_report(results: list[PrecisionResult]) -> dict:
    passed = [r for r in results if r.passed]
    failed = [r for r in results if not r.passed]
    total_fp = sum(len(r.reportable_findings) for r in results)
    return {
        "suite": "precision-false-positive-regression",
        "total_cases": len(results),
        "passed_cases": len(passed),
        "failed_cases": len(failed),
        "total_reportable_false_positives": total_fp,
        "results": [asdict(r) for r in results],
    }


# ---------------------------------------------------------------------------
# Live corpus (VPS): a JSON list of {id, name, chain, address, label, reason},
# where label in {"safe", "not_deployed"} means the address MUST NOT produce a
# reportable finding when scanned through the real pipeline.
# ---------------------------------------------------------------------------
def load_precision_corpus(path: str | Path) -> list[PrecisionCase]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases: list[PrecisionCase] = []
    for row in data:
        cases.append(PrecisionCase(
            id=str(row.get("id") or row.get("address")),
            name=str(row.get("name") or row.get("id") or row.get("address")),
            chain=str(row.get("chain") or "ethereum"),
            reason=str(row.get("reason") or row.get("label") or "must stay silent"),
            address=str(row.get("address") or ""),
            allow_reportable=bool(row.get("allow_reportable", False)),
        ))
    return cases


async def run_live_precision_scans(
    cases: Iterable[PrecisionCase],
    *,
    profile: str = "ultra-deep-v2",
    name_prefix: str = "precision-corpus",
) -> list[int]:
    """Scan corpus addresses through the REAL pipeline (needs RPC + Etherscan keys).

    Mirrors ``exploit_benchmark.run_benchmark_scans``: one scan per chain. Returns the
    scan ids to validate. Only cases with an ``address`` are scanned.
    """
    from ..database import SessionLocal, init_db
    from ..models import Scan, ScanStatus, Target
    from .scanner import manager, run_scan_pipeline

    init_db()
    scan_ids: list[int] = []
    grouped: dict[str, list[PrecisionCase]] = {}
    for case in cases:
        if case.address:
            grouped.setdefault(case.chain, []).append(case)

    for chain, chain_cases in grouped.items():
        with SessionLocal() as db:
            scan = Scan(
                name=f"{name_prefix}-{chain}",
                chain=chain,
                scan_profile=profile,
                total_targets=len(chain_cases),
                status=ScanStatus.QUEUED,
                toggles={},
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            scan_id = scan.id
            for case in chain_cases:
                db.add(Target(scan_id=scan_id, address=case.address, chain=chain, label=case.id))
            db.commit()
        scan_ids.append(scan_id)
        await run_scan_pipeline(scan_id, manager)
    return scan_ids


def validate_live_precision(db, scan_ids: list[int], cases: Iterable[PrecisionCase]) -> list[PrecisionResult]:
    """After a live scan, flag any corpus address that produced a reportable finding."""
    from sqlalchemy import select
    from ..models import Finding, Target

    results: list[PrecisionResult] = []
    for case in cases:
        if not case.address:
            continue
        result = PrecisionResult(case_id=case.id, name=case.name, passed=False)
        target = None
        stmt = (
            select(Target)
            .where(Target.scan_id.in_(scan_ids), Target.chain == case.chain)
            .order_by(Target.id.desc())
        )
        for t in db.scalars(stmt):
            if t.address.lower() == case.address.lower():
                target = t
                break
        if target is None:
            result.errors.append("target not found in scan results")
        else:
            findings = db.scalars(select(Finding).where(Finding.target_id == target.id)).all()
            result.total_candidates = len(findings)
            for f in findings:
                if f.classification in REPORTABLE:
                    result.reportable_findings.append({
                        "detector": f.detector,
                        "title": (f.title or "")[:140],
                        "classification": str(f.classification),
                    })
        result.passed = case.allow_reportable or not result.reportable_findings
        results.append(result)
    return results
