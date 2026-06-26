"""Fuzz-readiness checks and starter Foundry fuzz-suite generation.

Phase 1/2 scope:
  * detect existing Foundry/Echidna/Medusa/Halmos fuzz assets,
  * run existing Foundry fuzz/invariant tests when the target workspace is a
    real Foundry project,
  * generate a standalone Foundry starter suite from ABI/source signals.

The generated suite is scaffolding, not proof. It is saved for the auditor and
validated with `forge test --list` when forge is installed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..detectors.base import FindingCandidate, TargetContext
from ..runners.base import RunnerResult
from .command_runner import run_command, which


FUZZ_TEST_RE = re.compile(r"\b(testFuzz\w*|invariant_\w*|statefulFuzz\w*)\b")
ECHIDNA_RE = re.compile(r"\bechidna_\w+\s*\(")

SURFACE_RULES: list[tuple[str, re.Pattern, list[str]]] = [
    (
        "vault/share accounting",
        re.compile(r"deposit|withdraw|redeem|mint|shares?|totalAssets|convertToShares", re.I),
        [
            "assets held by the vault should cover all redeemable shares",
            "deposit->withdraw round trips should not create profit except documented fees",
            "direct token donations should not inflate later depositor losses",
        ],
    ),
    (
        "lending solvency",
        re.compile(r"borrow|repay|liquidat|collateral|health|debt|reserve", re.I),
        [
            "a borrower should not increase debt or withdraw collateral while unhealthy",
            "donations/reserve mutations should not bypass health checks",
            "liquidation should reduce bad debt and never create free collateral",
        ],
    ),
    (
        "AMM/oracle math",
        re.compile(r"swap|getReserves|slot0|price|oracle|sqrtP|tick|liquidity", re.I),
        [
            "price output should remain bounded under one-block reserve skew",
            "swap steps around tick boundaries should cross liquidity exactly once",
            "rounding should favor the pool on exits and exact-output paths",
        ],
    ),
    (
        "rewards/checkpoints",
        re.compile(r"claim|reward|checkpoint|royalt|settle|record|cumulative", re.I),
        [
            "claimable rewards should never exceed deposited/earned rewards",
            "zero-value transfers should not append new reward checkpoints",
            "repeated settle/claim calls in one epoch should be idempotent",
        ],
    ),
    (
        "bridge/proof replay",
        re.compile(r"bridge|root|proof|message|relay|nonce|domain|verifier", re.I),
        [
            "each message/root/nonce can be consumed at most once",
            "source chain, destination chain, sender, receiver, and nonce are domain-bound",
            "zero/unset roots and untrusted verifiers should never authorize value movement",
        ],
    ),
    (
        "token/allowance flows",
        re.compile(r"transferFrom|approve|permit|allowance|transfer|safeTransfer", re.I),
        [
            "caller-supplied from addresses must be msg.sender-bound or authorized",
            "zero-amount transfers should not unlock paid/rewarded paths",
            "allowances should not be drainable through arbitrary target+calldata routers",
        ],
    ),
]


@dataclass(frozen=True)
class DetectorInvariantTemplate:
    key: str
    match_patterns: tuple[str, ...]
    function_patterns: tuple[str, ...]
    property_name: str
    goal: str
    next_assertion: str
    strategy: str


DETECTOR_INVARIANT_TEMPLATES: list[DetectorInvariantTemplate] = [
    DetectorInvariantTemplate(
        key="zero_transfer_reward_checkpoint",
        match_patterns=(
            "zero.transfer",
            "zero.value",
            "reward",
            "checkpoint",
            "royalt",
        ),
        function_patterns=("safeTransferFrom", "transferFrom", "transfer", "settle", "checkpoint", "record", "claim"),
        property_name="zero-value transfer reward/checkpoint idempotence",
        goal="Zero-value transfers and empty settlement updates must not append reward records or multiply claims.",
        next_assertion="Snapshot reward-record count or claimable amount before/after repeated zero-value transfers, then require no positive delta.",
        strategy="zero_transfer",
    ),
    DetectorInvariantTemplate(
        key="donation_share_inflation",
        match_patterns=(
            "donation",
            "share",
            "vault",
            "erc4626",
            "exchange.rate",
            "totalassets",
            "reserve",
            "inflation",
        ),
        function_patterns=("deposit", "mint", "withdraw", "redeem", "donate", "sync", "skim", "repay", "borrow"),
        property_name="donation/share-price safety",
        goal="Direct donations or reserve mutations must not let an attacker inflate share price and steal later deposits.",
        next_assertion="Model attacker donation plus honest deposit/withdraw round trip, then require honest user assets are conserved within documented fees.",
        strategy="donation_share",
    ),
    DetectorInvariantTemplate(
        key="oracle_amm_rounding",
        match_patterns=(
            "oracle",
            "price",
            "twap",
            "spot",
            "amm",
            "clmm",
            "tick",
            "rounding",
            "precision",
            "liquidity",
        ),
        function_patterns=("swap", "quote", "price", "slot0", "getReserves", "liquidate", "borrow", "withdraw"),
        property_name="oracle/AMM bounded manipulation",
        goal="One-block reserve skew, tick-boundary math, or precision loss must not create unbounded borrow, liquidation, or withdrawal profit.",
        next_assertion="Add fork or mocked-pool reserves, compare pre/post quoted value, and require output stays inside a protocol-specific bound.",
        strategy="oracle_rounding",
    ),
    DetectorInvariantTemplate(
        key="bridge_proof_replay",
        match_patterns=(
            "bridge",
            "proof",
            "root",
            "replay",
            "verifier",
            "domain",
            "message",
            "settlement",
            "settlement.boundary",
            "settlement_boundary",
            "zk",
            "retry",
            "zero.root",
        ),
        function_patterns=("process", "relay", "execute", "prove", "verify", "finalize", "consume", "claim"),
        property_name="bridge/proof domain and replay safety",
        goal="Zero roots, untrusted verifiers, retry paths, or coordinate-domain mismatches must not authorize value movement twice.",
        next_assertion="Call the same message/root/nonce twice and require the second call cannot increase minted/unlocked balance or consumed count.",
        strategy="bridge_zero_root",
    ),
    DetectorInvariantTemplate(
        key="callback_reentrancy",
        match_patterns=(
            "reentr",
            "callback",
            "hook",
            "erc777",
            "erc1155",
            "receiver",
            "onerc",
            "read.only",
        ),
        function_patterns=("withdraw", "redeem", "claim", "safeTransfer", "transfer", "callback", "execute"),
        property_name="callback/reentrancy accounting safety",
        goal="Token hooks or read-only callbacks must not observe stale accounting or let balances be consumed twice.",
        next_assertion="Replace this probe with an attacker receiver/handler and require owed balance decreases before any external callback.",
        strategy="callback_reentrancy",
    ),
    DetectorInvariantTemplate(
        key="allowance_router_drain",
        match_patterns=(
            "allowance",
            "arbitrary.from",
            "transferfrom",
            "router",
            "arbitrary.call",
            "permit",
            "approval",
        ),
        function_patterns=("transferFrom", "execute", "route", "swap", "approve", "permit", "multicall"),
        property_name="allowance/router provenance safety",
        goal="Caller-supplied from addresses, arbitrary calldata routers, and permit paths must stay bound to the authorized signer.",
        next_assertion="Model victim approval plus attacker route and require victim balance cannot decrease unless msg.sender is authorized.",
        strategy="allowance_router",
    ),
    DetectorInvariantTemplate(
        key="auth_upgrade_provenance",
        match_patterns=(
            "initialize",
            "initializer",
            "uninitialized",
            "owner",
            "admin",
            "delegatecall",
            "implementation",
            "upgrade",
            "verifier.setter",
        ),
        function_patterns=("initialize", "init", "set", "upgrade", "delegate", "execute", "transferOwnership"),
        property_name="auth/upgrade provenance safety",
        goal="Initialization, upgrade, delegatecall, and verifier setter paths must not be reachable by an unprivileged caller.",
        next_assertion="Add attacker-role calls for the selected entry point and require privileged state is unchanged after any unauthorized attempt.",
        strategy="auth_upgrade",
    ),
]

GENERIC_DETECTOR_TEMPLATE = DetectorInvariantTemplate(
    key="generic_detector_probe",
    match_patterns=(),
    function_patterns=("withdraw", "claim", "deposit", "mint", "transfer", "execute", "process", "set"),
    property_name="detector-guided state safety",
    goal="The flagged state transition should preserve protocol value, authorization, replay, and lifecycle invariants.",
    next_assertion="Replace the low-level probe with a target-specific assertion over the state variable named in the detector evidence.",
    strategy="generic",
)

SUPPORTED_ABI_TYPES = {
    "address": "address",
    "bool": "bool",
    "bytes": "bytes memory",
    "string": "string memory",
    "bytes32": "bytes32",
}


@dataclass
class GeneratedSuite:
    project_dir: Path
    test_path: Path
    plan_path: Path
    fuzz_tests: int
    skipped_functions: list[str] = field(default_factory=list)
    surfaces: list[str] = field(default_factory=list)


def inspect_fuzz_readiness(source_dir: Path, source_files: dict[str, str]) -> dict:
    """Return a compact inventory of existing fuzz assets."""
    sol_tests = list(source_dir.rglob("*.t.sol")) if source_dir.exists() else []
    all_text = "\n".join(source_files.values())

    foundry_toml = source_dir / "foundry.toml"
    hardhat_config = any((source_dir / name).exists() for name in ("hardhat.config.ts", "hardhat.config.js"))
    echidna_configs = [
        str(p.relative_to(source_dir))
        for p in source_dir.rglob("*")
        if p.is_file() and p.name.lower() in {"echidna.yaml", "echidna.yml", "echidna.config.yaml"}
    ] if source_dir.exists() else []
    medusa_configs = [
        str(p.relative_to(source_dir))
        for p in source_dir.rglob("*")
        if p.is_file() and p.name.lower() in {"medusa.json", "medusa.yaml", "medusa.yml"}
    ] if source_dir.exists() else []
    halmos_configs = [
        str(p.relative_to(source_dir))
        for p in source_dir.rglob("*")
        if p.is_file() and p.name.lower() in {"halmos.toml", "halmos.config.toml"}
    ] if source_dir.exists() else []

    fuzz_files: list[str] = []
    invariant_files: list[str] = []
    for p in sol_tests:
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if FUZZ_TEST_RE.search(txt):
            fuzz_files.append(str(p.relative_to(source_dir)))
        if re.search(r"\binvariant_\w+\s*\(", txt):
            invariant_files.append(str(p.relative_to(source_dir)))

    echidna_properties = len(ECHIDNA_RE.findall(all_text))
    surfaces = infer_surfaces(all_text)
    return {
        "foundry_project": foundry_toml.exists(),
        "hardhat_project": hardhat_config,
        "foundry_fuzz_files": fuzz_files,
        "foundry_invariant_files": invariant_files,
        "echidna_configs": echidna_configs,
        "echidna_properties": echidna_properties,
        "medusa_configs": medusa_configs,
        "halmos_configs": halmos_configs,
        "surfaces": surfaces,
        "recommended_next": _recommended_next(surfaces, bool(fuzz_files or invariant_files or echidna_properties)),
    }


def infer_surfaces(text: str) -> list[str]:
    surfaces = [name for name, pat, _ideas in SURFACE_RULES if pat.search(text or "")]
    return surfaces or ["generic external-call state machine"]


def _recommended_next(surfaces: list[str], has_existing: bool) -> list[str]:
    out: list[str] = []
    if has_existing:
        out.append("run existing fuzz/invariant suite and inspect failures/timeouts")
    else:
        out.append("review generated Foundry starter suite and replace smoke checks with protocol-specific invariants")
    for name, _pat, ideas in SURFACE_RULES:
        if name in surfaces:
            out.extend(ideas[:2])
    return out[:8]


def run_fuzzing(
    ctx: TargetContext,
    *,
    source_dir: Path,
    out_dir: Path,
    timeout: int = 180,
) -> RunnerResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    readiness = inspect_fuzz_readiness(source_dir, ctx.source_files)
    (out_dir / "fuzz_readiness.json").write_text(
        json.dumps(readiness, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    existing = _run_existing_foundry_fuzz(source_dir, out_dir / "existing_foundry", timeout=timeout)
    existing_echidna = _run_existing_echidna_fuzz(
        source_dir, readiness, out_dir / "existing_echidna", timeout=timeout
    )
    existing_medusa = _run_existing_medusa_fuzz(
        source_dir, readiness, out_dir / "existing_medusa", timeout=timeout
    )
    generated = generate_foundry_starter_suite(ctx, out_dir / "generated_foundry", readiness=readiness)
    generated_validation = _validate_generated_suite(generated.project_dir, out_dir / "generated_validation", timeout=timeout)

    summary = (
        f"fuzz readiness: surfaces={', '.join(readiness['surfaces'])}; "
        f"existing_foundry={existing.status}; existing_echidna={existing_echidna.status}; "
        f"existing_medusa={existing_medusa.status}; generated_foundry={generated.fuzz_tests} fuzz test(s); "
        f"path={generated.project_dir}"
    )
    if generated_validation.status not in {"ok", "skipped"}:
        summary += f"; generated validation={generated_validation.status}"

    result = RunnerResult(
        tool_name="fuzzing",
        status="ok",
        command=generated_validation.command or existing.command,
        exit_code=generated_validation.exit_code,
        timed_out=generated_validation.timed_out,
        stdout_path=generated_validation.stdout_path,
        stderr_path=generated_validation.stderr_path,
        summary=summary,
        findings=[],
        meta={
            "readiness": readiness,
            "generated_project": str(generated.project_dir),
            "generated_test": str(generated.test_path),
            "generated_plan": str(generated.plan_path),
            "generated_fuzz_tests": generated.fuzz_tests,
            "skipped_functions": generated.skipped_functions,
            "existing_foundry": {
                "status": existing.status,
                "summary": existing.summary,
                "command": existing.command,
                "stdout_path": existing.stdout_path,
                "stderr_path": existing.stderr_path,
            },
            "existing_echidna": {
                "status": existing_echidna.status,
                "summary": existing_echidna.summary,
                "command": existing_echidna.command,
                "stdout_path": existing_echidna.stdout_path,
                "stderr_path": existing_echidna.stderr_path,
            },
            "existing_medusa": {
                "status": existing_medusa.status,
                "summary": existing_medusa.summary,
                "command": existing_medusa.command,
                "stdout_path": existing_medusa.stdout_path,
                "stderr_path": existing_medusa.stderr_path,
            },
            "generated_validation": {
                "status": generated_validation.status,
                "summary": generated_validation.summary,
                "command": generated_validation.command,
                "stdout_path": generated_validation.stdout_path,
                "stderr_path": generated_validation.stderr_path,
            },
        },
    )
    failing_existing = next(
        (r for r in (existing, existing_echidna, existing_medusa) if r.status in {"failed", "timeout"}),
        None,
    )
    if failing_existing is not None:
        existing = failing_existing
        result.status = existing.status
        result.summary = f"existing {existing.tool_name} suite {existing.status}: {existing.summary}"
        result.command = existing.command
        result.exit_code = existing.exit_code
        result.timed_out = existing.timed_out
        result.stdout_path = existing.stdout_path
        result.stderr_path = existing.stderr_path
    elif generated_validation.status == "failed":
        result.status = "failed"
        result.summary = f"generated fuzz suite did not compile/list cleanly: {generated_validation.summary}"
        result.command = generated_validation.command
        result.exit_code = generated_validation.exit_code
        result.stdout_path = generated_validation.stdout_path
        result.stderr_path = generated_validation.stderr_path
    summary_path = out_dir / "fuzz_summary.json"
    summary_path.write_text(json.dumps(result.meta, indent=2, sort_keys=True, default=str), encoding="utf-8")
    result.json_output_path = str(summary_path)
    return result


def run_detector_invariant_generation(
    ctx: TargetContext,
    candidates: list[FindingCandidate],
    out_dir: Path,
    *,
    timeout: int = 180,
    max_findings: int = 8,
) -> RunnerResult:
    """Generate and validate detector-guided Foundry invariant probes.

    This is Elite phase 1: detector findings choose the invariant focus, while
    the generated Solidity remains a compiling scaffold until a later stateful
    handler/assertion pass turns each probe into proof-grade fuzzing.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    selected = _select_detector_invariant_candidates(candidates, max_findings=max_findings)
    summary_path = out_dir / "detector_invariant_summary.json"
    if not selected:
        meta = {
            "target": ctx.address,
            "chain": ctx.chain,
            "selected_findings": [],
            "reason": "no high-signal detector findings",
        }
        summary_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        res = RunnerResult.skipped("fuzz-invariants", "no high-signal detector findings to convert into invariants")
        res.meta = meta
        res.json_output_path = str(summary_path)
        return res

    generated = generate_detector_invariant_suite(ctx, selected, out_dir, max_findings=max_findings)
    validation = _validate_generated_suite(generated.project_dir, out_dir / "validation", timeout=timeout)
    status = "failed" if validation.status == "failed" else "ok"
    summary = (
        f"detector-focused invariants: {generated.fuzz_tests} probe(s) for "
        f"{len(selected)} high-signal finding(s); validation={validation.status}; "
        f"path={generated.project_dir}"
    )
    result = RunnerResult(
        tool_name="fuzz-invariants",
        status=status,
        command=validation.command,
        exit_code=validation.exit_code,
        timed_out=validation.timed_out,
        stdout_path=validation.stdout_path,
        stderr_path=validation.stderr_path,
        summary=summary,
        findings=[],
        meta={
            "target": ctx.address,
            "chain": ctx.chain,
            "generated_project": str(generated.project_dir),
            "generated_test": str(generated.test_path),
            "generated_plan": str(generated.plan_path),
            "generated_fuzz_tests": generated.fuzz_tests,
            "selected_findings": [_candidate_summary(c) for c in selected],
            "templates": generated.surfaces,
            "validation": {
                "status": validation.status,
                "summary": validation.summary,
                "command": validation.command,
                "stdout_path": validation.stdout_path,
                "stderr_path": validation.stderr_path,
            },
        },
    )
    summary_path.write_text(json.dumps(result.meta, indent=2, sort_keys=True, default=str), encoding="utf-8")
    result.json_output_path = str(summary_path)
    return result


def generate_detector_invariant_suite(
    ctx: TargetContext,
    candidates: list[FindingCandidate],
    out_dir: Path,
    *,
    max_findings: int = 8,
) -> GeneratedSuite:
    project_dir = out_dir
    test_dir = project_dir / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "src").mkdir(parents=True, exist_ok=True)
    (project_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")

    selected = _select_detector_invariant_candidates(candidates, max_findings=max_findings)
    abi_functions = _abi_functions(ctx.abi)
    generated: list[str] = []
    rows: list[dict] = []
    template_keys: list[str] = []
    skipped: list[str] = []

    for index, cand in enumerate(selected):
        template = _template_for_candidate(cand)
        fn = _find_detector_abi_function(cand, template, abi_functions)
        probe = _render_detector_probe(index, cand, template, fn)
        generated.append(probe)
        template_keys.append(template.key)
        rows.append(
            {
                "index": index,
                "function_name": f"testFuzz_detector_{_safe_identifier(template.key)}_{index}",
                "detector": cand.detector,
                "rule_id": (cand.evidence or {}).get("rule_id") or "",
                "title": cand.title,
                "template": template.key,
                "property_name": template.property_name,
                "goal": template.goal,
                "next_assertion": template.next_assertion,
                "abi_signature": _signature(fn) if fn else "raw calldata fallback",
            }
        )
        if fn is None:
            skipped.append(f"{cand.detector}: raw calldata fallback")

    test_path = test_dir / "BulkAuditDetectorInvariants.t.sol"
    test_path.write_text(_render_detector_invariant_test(ctx.address, generated), encoding="utf-8")
    plan_path = project_dir / "DETECTOR_INVARIANTS.md"
    plan_path.write_text(_render_detector_invariant_plan(ctx, rows), encoding="utf-8")
    return GeneratedSuite(
        project_dir=project_dir,
        test_path=test_path,
        plan_path=plan_path,
        fuzz_tests=len(generated),
        skipped_functions=skipped,
        surfaces=list(dict.fromkeys(template_keys)),
    )


def _select_detector_invariant_candidates(
    candidates: list[FindingCandidate],
    *,
    max_findings: int,
) -> list[FindingCandidate]:
    selected: list[FindingCandidate] = []
    for cand in candidates:
        evidence = cand.evidence or {}
        if evidence.get("informational") or evidence.get("refuted"):
            continue
        severity = (cand.severity_candidate or "").lower()
        evidence_text = json.dumps(evidence, default=str).lower()
        high_signal = (
            cand.impact_score >= 7
            or severity in {"critical", "high"}
            or "confirmable" in evidence_text
            or evidence.get("poc_passed") is True
            or evidence.get("manipulation_confirmed") is True
        )
        if high_signal:
            selected.append(cand)
    selected.sort(
        key=lambda c: (
            0 if (c.severity_candidate or "").lower() == "critical" else 1,
            -float(c.impact_score or 0),
            -float(c.confidence_score or 0),
            c.detector,
        )
    )
    return selected[:max_findings]


def _candidate_summary(cand: FindingCandidate) -> dict:
    evidence = cand.evidence or {}
    return {
        "detector": cand.detector,
        "title": cand.title,
        "severity": cand.severity_candidate,
        "impact_score": cand.impact_score,
        "confidence_score": cand.confidence_score,
        "rule_id": evidence.get("rule_id") or "",
        "affected_functions": cand.affected_functions or [],
    }


def _candidate_text(cand: FindingCandidate) -> str:
    evidence = cand.evidence or {}
    evidence_bits = " ".join(
        str(evidence.get(k) or "")
        for k in ("rule_id", "check", "pattern", "family", "root_cause", "incident")
    )
    return " ".join(
        [
            cand.detector or "",
            cand.title or "",
            cand.description or "",
            evidence_bits,
            " ".join(cand.affected_functions or []),
        ]
    ).lower()


def _template_for_candidate(cand: FindingCandidate) -> DetectorInvariantTemplate:
    text = _candidate_text(cand)
    scored: list[tuple[int, DetectorInvariantTemplate]] = []
    for template in DETECTOR_INVARIANT_TEMPLATES:
        score = sum(1 for pat in template.match_patterns if re.search(pat, text, re.I))
        if score:
            scored.append((score, template))
    if scored:
        scored.sort(key=lambda item: item[0], reverse=True)
        return scored[0][1]
    return GENERIC_DETECTOR_TEMPLATE


def _find_detector_abi_function(
    cand: FindingCandidate,
    template: DetectorInvariantTemplate,
    abi_functions: list[dict],
) -> dict | None:
    supported = [fn for fn in abi_functions if _supports_focused_probe(fn)]
    if not supported:
        return None

    affected_names = []
    for item in cand.affected_functions or []:
        name = re.sub(r"\(.*$", "", item or "").strip()
        if name:
            affected_names.append(name.lower())
    for fn in supported:
        if (fn.get("name") or "").lower() in affected_names:
            return fn

    for pattern in template.function_patterns:
        for fn in supported:
            if re.search(pattern, fn.get("name") or "", re.I):
                return fn
    return None


def _supports_focused_probe(fn: dict) -> bool:
    inputs = fn.get("inputs") or []
    if len(inputs) > 6:
        return False
    return all(_sol_type(str(inp.get("type") or "")) is not None for inp in inputs if isinstance(inp, dict))


def _render_detector_probe(
    index: int,
    cand: FindingCandidate,
    template: DetectorInvariantTemplate,
    fn: dict | None,
) -> str:
    func_name = f"testFuzz_detector_{_safe_identifier(template.key)}_{index}"
    detector = _sol_string(cand.detector or template.key)
    prop = _sol_string(template.property_name)
    goal = _sol_comment(template.goal)
    rule_id = _sol_comment(str((cand.evidence or {}).get("rule_id") or ""))
    title = _sol_comment(cand.title or "")

    if fn is None:
        return f"""
    // Detector: {detector}; Rule: {rule_id}
    // Finding: {title}
    // Property goal: {goal}
    function {func_name}(bytes calldata payload) public {{
        _probe("{detector}", "{prop}", payload);
    }}
"""

    rendered = _render_detector_call(fn, template.strategy)
    if rendered is None:
        return f"""
    // Detector: {detector}; Rule: {rule_id}
    // Finding: {title}
    // Property goal: {goal}
    function {func_name}(bytes calldata payload) public {{
        _probe("{detector}", "{prop}", payload);
    }}
"""

    params_blob, data_expr = rendered
    return f"""
    // Detector: {detector}; Rule: {rule_id}
    // Finding: {title}
    // Property goal: {goal}
    function {func_name}({params_blob}) public {{
        _probe("{detector}", "{prop}", {data_expr});
    }}
"""


def _render_detector_call(fn: dict, strategy: str) -> tuple[str, str] | None:
    inputs = fn.get("inputs") or []
    params: list[str] = []
    args: list[str] = []
    used_names: set[str] = set()
    for i, inp in enumerate(inputs):
        if not isinstance(inp, dict):
            return None
        abi_type = str(inp.get("type") or "")
        sol_type = _sol_type(abi_type)
        if sol_type is None:
            return None
        expr = _detector_arg_override(strategy, fn, inputs, i)
        if expr is None:
            param_name = _unique_param_name(inp.get("name") or f"arg{i}", i, used_names)
            params.append(f"{sol_type} {param_name}")
            args.append(param_name)
        else:
            args.append(expr)

    sig = _signature(fn)
    args_blob = (", " + ", ".join(args)) if args else ""
    return ", ".join(params), f'abi.encodeWithSelector(bytes4(keccak256(bytes("{sig}"))){args_blob})'


def _detector_arg_override(strategy: str, fn: dict, inputs: list[dict], index: int) -> str | None:
    inp = inputs[index] if index < len(inputs) else {}
    abi_type = str(inp.get("type") or "")
    raw_name = str(inp.get("name") or "").lower()
    fn_name = str(fn.get("name") or "").lower()

    if strategy == "zero_transfer" and _is_zero_amount_input(fn_name, inputs, index):
        return _typed_zero_expr(abi_type)
    if strategy == "bridge_zero_root":
        if abi_type == "bytes32" and re.search(r"root|hash|commit|message|id", raw_name):
            return "bytes32(0)"
        if abi_type == "address" and re.search(r"verifier|peer|endpoint|sender|receiver", raw_name):
            return "address(0)"
    if strategy == "auth_upgrade":
        if abi_type == "address" and re.search(r"owner|admin|implementation|verifier|target", raw_name):
            return "address(0)"
    return None


def _is_zero_amount_input(fn_name: str, inputs: list[dict], index: int) -> bool:
    inp = inputs[index] if index < len(inputs) else {}
    abi_type = str(inp.get("type") or "")
    raw_name = str(inp.get("name") or "").lower()
    if not re.fullmatch(r"u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", abi_type):
        return False
    if re.search(r"amount|value|qty|quantity|shares?|assets?|balance|reward", raw_name):
        return True
    numeric_indexes = [
        i for i, candidate in enumerate(inputs)
        if isinstance(candidate, dict)
        and re.fullmatch(
            r"u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?",
            str(candidate.get("type") or ""),
        )
    ]
    if re.search(r"transfer|settle|claim|checkpoint|record", fn_name) and numeric_indexes:
        return index == numeric_indexes[-1]
    return False


def _typed_zero_expr(abi_type: str) -> str:
    if abi_type.startswith("uint"):
        return "uint256(0)"
    if abi_type.startswith("int"):
        return "int256(0)"
    if abi_type == "address":
        return "address(0)"
    if abi_type == "bool":
        return "false"
    if abi_type == "bytes":
        return '""'
    if abi_type == "string":
        return '""'
    if abi_type.startswith("bytes"):
        return "bytes32(0)"
    return "uint256(0)"


def _render_detector_invariant_test(address: str, functions: list[str]) -> str:
    target_literal = _address_literal(address)
    body = "\n".join(functions) if functions else """
    function testFuzz_detector_raw(bytes calldata payload) public {
        _probe("generic", "raw calldata", payload);
    }
"""
    return f"""// SPDX-License-Identifier: MIT
// AUTO-GENERATED by BulkAuditAI Elite fuzzing phase 1.
// Detector findings choose the focus. This scaffold records probe behavior; add
// target-specific state snapshots to turn each probe into a proof-grade invariant.
pragma solidity ^0.8.23;

contract BulkAuditDetectorInvariants {{
    address internal constant TARGET = {target_literal};
    uint256 public detectorCalls;
    uint256 public detectorSuccesses;

    event DetectorProbe(string detector, string propertyName, bytes data, bool ok, bytes ret);

    receive() external payable {{}}

    function test_target_has_code() public view {{
        require(TARGET.code.length > 0, "target has no code; run on a fork or replace TARGET");
    }}

    function invariant_target_code_persists() public view {{
        require(TARGET.code.length > 0, "target code disappeared");
    }}

    function _probe(string memory detector, string memory propertyName, bytes memory data) internal {{
        detectorCalls++;
        (bool ok, bytes memory ret) = TARGET.call(data);
        if (ok) detectorSuccesses++;
        emit DetectorProbe(detector, propertyName, data, ok, ret);
    }}
{body}
}}
"""


def _render_detector_invariant_plan(ctx: TargetContext, rows: list[dict]) -> str:
    if rows:
        row_text = "\n\n".join(
            "\n".join(
                [
                    f"### {row['function_name']}",
                    f"- Detector: `{row['detector']}`",
                    f"- Rule: `{row['rule_id'] or 'unknown'}`",
                    f"- Finding: {row['title']}",
                    f"- Template: `{row['template']}`",
                    f"- ABI probe: `{row['abi_signature']}`",
                    f"- Property: {row['property_name']}",
                    f"- Property goal: {row['goal']}",
                    f"- Next manual assertion: {row['next_assertion']}",
                ]
            )
            for row in rows
        )
    else:
        row_text = "No high-signal detector findings were selected for invariant generation."

    return f"""# BulkAuditAI Detector Invariants

Target: `{ctx.address}`
Chain: `{ctx.chain}`
Contract: `{ctx.contract_name or 'unknown'}`

This Foundry project is generated from detector findings after deduplication.
It is intentionally conservative: probes are compiled and listed automatically,
but the next Elite phase must add stateful handlers and concrete assertions.

## Generated Probes

{row_text}

## Next Phase

Elite phase 2 should convert each probe into a stateful handler with attacker
and honest-user actors, fork or mock asset balances, and assertions that prove
or refute the detector hypothesis automatically.
"""


def _unique_param_name(raw: str, index: int, used: set[str]) -> str:
    name = _safe_param_name(raw, index)
    base = name
    suffix = 1
    while name in used:
        name = f"{base}_{suffix}"
        suffix += 1
    used.add(name)
    return name


def _sol_string(raw: str) -> str:
    return (raw or "").replace("\\", "\\\\").replace('"', '\\"')[:96]


def _sol_comment(raw: str) -> str:
    text = re.sub(r"\s+", " ", raw or "").replace("*/", "* /").strip()
    return text[:220]


def _run_existing_foundry_fuzz(source_dir: Path, out_dir: Path, *, timeout: int) -> RunnerResult:
    if not (source_dir / "foundry.toml").exists():
        return RunnerResult.skipped("foundry-fuzz", "no foundry.toml in fetched/source workspace")
    if which("forge") is None:
        return RunnerResult.skipped("foundry-fuzz", "forge not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = run_command(
        ["forge", "test", "--json", "--match-test", "(testFuzz|invariant_)"],
        cwd=source_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="forge_fuzz",
    )
    res = RunnerResult.from_command("foundry-fuzz", cmd)
    if res.status == "ok":
        res.summary = "existing Foundry fuzz/invariant suite ran"
    elif res.status == "failed":
        res.summary = "existing Foundry fuzz/invariant suite failed"
    elif res.status == "timeout":
        res.summary = "existing Foundry fuzz/invariant suite timed out"
    return res


def _run_existing_echidna_fuzz(
    source_dir: Path, readiness: dict, out_dir: Path, *, timeout: int
) -> RunnerResult:
    configs = readiness.get("echidna_configs") or []
    has_properties = bool(readiness.get("echidna_properties"))
    if not configs and not has_properties:
        return RunnerResult.skipped("echidna-fuzz", "no echidna config/properties detected")
    exe = "echidna" if which("echidna") else "echidna-test" if which("echidna-test") else ""
    if not exe:
        return RunnerResult.skipped("echidna-fuzz", "echidna not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    args = [exe, "."]
    if configs:
        args += ["--config", configs[0]]
    cmd = run_command(
        args,
        cwd=source_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="echidna_fuzz",
    )
    res = RunnerResult.from_command("echidna-fuzz", cmd)
    res.summary = "existing Echidna campaign ran" if res.status == "ok" else f"existing Echidna campaign {res.status}"
    return res


def _run_existing_medusa_fuzz(
    source_dir: Path, readiness: dict, out_dir: Path, *, timeout: int
) -> RunnerResult:
    configs = readiness.get("medusa_configs") or []
    if not configs:
        return RunnerResult.skipped("medusa-fuzz", "no medusa config detected")
    if which("medusa") is None:
        return RunnerResult.skipped("medusa-fuzz", "medusa not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = run_command(
        ["medusa", "fuzz", "--config", configs[0], "--no-color"],
        cwd=source_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="medusa_fuzz",
    )
    res = RunnerResult.from_command("medusa-fuzz", cmd)
    res.summary = "existing Medusa campaign ran" if res.status == "ok" else f"existing Medusa campaign {res.status}"
    return res


def _validate_generated_suite(project_dir: Path, out_dir: Path, *, timeout: int) -> RunnerResult:
    if which("forge") is None:
        return RunnerResult.skipped("generated-foundry-fuzz", "forge not installed")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = run_command(
        ["forge", "test", "--list"],
        cwd=project_dir,
        timeout=timeout,
        output_dir=out_dir,
        output_prefix="forge_generated_list",
    )
    res = RunnerResult.from_command("generated-foundry-fuzz", cmd)
    res.summary = "generated Foundry suite listed successfully" if res.status == "ok" else "generated Foundry suite failed to list"
    return res


def generate_foundry_starter_suite(
    ctx: TargetContext,
    out_dir: Path,
    *,
    readiness: dict | None = None,
    max_functions: int = 18,
) -> GeneratedSuite:
    project_dir = out_dir
    test_dir = project_dir / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "src").mkdir(parents=True, exist_ok=True)
    (project_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")

    abi_functions = _abi_functions(ctx.abi)
    generated: list[str] = []
    skipped: list[str] = []
    for idx, fn in enumerate(abi_functions):
        if len(generated) >= max_functions:
            skipped.append(f"{fn['name']} (cap reached)")
            continue
        maybe = _render_fuzz_function(idx, fn)
        if maybe:
            generated.append(maybe)
        else:
            skipped.append(_signature(fn))

    surfaces = (readiness or {}).get("surfaces") or infer_surfaces(ctx.all_source_text())
    test_path = test_dir / "BulkAuditGeneratedFuzz.t.sol"
    test_path.write_text(_render_foundry_test(ctx.address, generated), encoding="utf-8")
    plan_path = project_dir / "FUZZ_PLAN.md"
    plan_path.write_text(_render_fuzz_plan(ctx, surfaces, generated, skipped), encoding="utf-8")
    return GeneratedSuite(
        project_dir=project_dir,
        test_path=test_path,
        plan_path=plan_path,
        fuzz_tests=len(generated),
        skipped_functions=skipped,
        surfaces=surfaces,
    )


def _foundry_toml() -> str:
    return """[profile.default]
src = "src"
test = "test"
out = "out"
libs = []
solc_version = "0.8.23"
optimizer = true
optimizer_runs = 200
fuzz = { runs = 128 }
invariant = { runs = 32, depth = 16 }
ffi = false
"""


def _abi_functions(abi: list | dict | None) -> list[dict]:
    items = abi if isinstance(abi, list) else []
    out = []
    for item in items:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        state = item.get("stateMutability") or ""
        name = item.get("name") or ""
        if not name or state in {"view", "pure"}:
            continue
        out.append(item)
    risk_order = ("claim", "withdraw", "redeem", "mint", "deposit", "borrow", "repay", "liquidat", "transfer", "approve", "permit", "execute", "relay", "process")
    return sorted(
        out,
        key=lambda f: min((i for i, pat in enumerate(risk_order) if pat in (f.get("name") or "").lower()), default=999),
    )


def _sol_type(abi_type: str) -> str | None:
    t = abi_type or ""
    if t in SUPPORTED_ABI_TYPES:
        return SUPPORTED_ABI_TYPES[t]
    if re.fullmatch(r"uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", t):
        return t
    if re.fullmatch(r"int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", t):
        return t
    if re.fullmatch(r"bytes([1-9]|[12][0-9]|3[0-2])", t):
        return t
    return None


def _render_fuzz_function(index: int, fn: dict) -> str | None:
    inputs = fn.get("inputs") or []
    if len(inputs) > 5:
        return None
    types: list[str] = []
    params: list[str] = []
    args: list[str] = []
    for i, inp in enumerate(inputs):
        abi_type = str(inp.get("type") or "")
        sol_type = _sol_type(abi_type)
        if sol_type is None:
            return None
        name = _safe_param_name(inp.get("name") or f"arg{i}", i)
        types.append(abi_type)
        params.append(f"{sol_type} {name}")
        args.append(name)
    sig = _signature(fn)
    safe_name = _safe_identifier(fn.get("name") or "fn")
    params_blob = ", ".join(params)
    args_blob = (", " + ", ".join(args)) if args else ""
    return f"""
    function testFuzz_{safe_name}_{index}({params_blob}) public {{
        _call(abi.encodeWithSelector(bytes4(keccak256(bytes("{sig}"))){args_blob}));
    }}
"""


def _signature(fn: dict) -> str:
    inputs = fn.get("inputs") or []
    types = ",".join(str(i.get("type") or "") for i in inputs if isinstance(i, dict))
    return f"{fn.get('name', '')}({types})"


def _safe_param_name(raw: str, index: int) -> str:
    name = _safe_identifier(raw or f"arg{index}")
    if name in {"from", "to", "value", "selector", "target"}:
        name = f"{name}_arg"
    return name or f"arg{index}"


def _safe_identifier(raw: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", raw or "")
    if not name or name[0].isdigit():
        name = f"arg_{name}"
    return name[:64]


def _render_foundry_test(address: str, functions: list[str]) -> str:
    target_literal = _address_literal(address)
    body = "\n".join(functions) if functions else """
    function testFuzz_rawCalldata(bytes calldata data) public {
        _call(data);
    }
"""
    return f"""// SPDX-License-Identifier: MIT
// AUTO-GENERATED by BulkAuditAI fuzzing phase 1/2.
// This is a starter suite. Reverts are recorded but not treated as failures
// because live fork state, roles, and balances may legitimately block calls.
pragma solidity ^0.8.23;

contract BulkAuditGeneratedFuzz {{
    address internal constant TARGET = {target_literal};
    uint256 public calls;
    uint256 public successes;

    event FuzzCall(bytes data, bool ok, bytes ret);

    receive() external payable {{}}

    function test_target_has_code() public view {{
        require(TARGET.code.length > 0, "target has no code; run on a fork or replace TARGET");
    }}

    function invariant_target_code_persists() public view {{
        require(TARGET.code.length > 0, "target code disappeared");
    }}

    function _call(bytes memory data) internal {{
        calls++;
        (bool ok, bytes memory ret) = TARGET.call(data);
        if (ok) successes++;
        emit FuzzCall(data, ok, ret);
    }}
{body}
}}
"""


def _address_literal(address: str) -> str:
    addr = (address or "").strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", addr):
        try:
            from eth_utils import to_checksum_address

            return f"address({to_checksum_address(addr)})"
        except Exception:
            return f"address(uint160({int(addr, 16)}))"
    return "address(0)"


def _render_fuzz_plan(ctx: TargetContext, surfaces: list[str], generated: list[str], skipped: list[str]) -> str:
    ideas: list[str] = []
    for name, _pat, surface_ideas in SURFACE_RULES:
        if name in surfaces:
            ideas.extend(surface_ideas)
    if not ideas:
        ideas = [
            "define value-conservation invariants for every asset the contract can custody",
            "model an unprivileged attacker and at least two honest users",
            "add sequence tests for every deposit/mutate/withdraw lifecycle",
        ]

    bullets = "\n".join(f"- {idea}" for idea in dict.fromkeys(ideas))
    skipped_blob = "\n".join(f"- {s}" for s in skipped[:30]) or "- none"
    return f"""# BulkAuditAI Fuzz Plan

Target: `{ctx.address}`
Chain: `{ctx.chain}`
Contract: `{ctx.contract_name or 'unknown'}`

## Generated Suite

- Foundry project: `generated_foundry`
- Generated ABI fuzz tests: {len(generated)}
- Skipped/unsupported ABI entries:
{skipped_blob}

## Detected Surfaces

{chr(10).join(f"- {s}" for s in surfaces)}

## Next Invariants To Build

{bullets}

## Elite Upgrade Path

- Convert each high-risk detector finding into one focused invariant.
- Add handler contracts that model attacker/honest-user roles and multi-step sequences.
- Run generated invariants with Foundry first, then export equivalent Echidna/Medusa campaigns.
"""
