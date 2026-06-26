from backend.core.bytecode_intel import _selector, analyze_bytecode
from backend.core.bytecode_probes import build_probe_plan, run_bytecode_probes


def _delegatecall_executor_meta():
    bytecode = "0x63" + _selector("execute(address,uint256,bytes)") + "1457f4"
    return analyze_bytecode(
        bytecode,
        address="0x1111111111111111111111111111111111111111",
        chain="ethereum",
        source_verified=False,
    )


def test_build_probe_plan_for_delegatecall_executor():
    meta = _delegatecall_executor_meta()

    plan = build_probe_plan(meta)

    assert plan["suite"] == "elite-phase-7-bytecode-selector-probes"
    assert plan["probe_count"] == 1
    probe = plan["probes"][0]
    assert probe["rule_id"] == "closed_source_delegatecall_executor"
    assert probe["signature"] == "execute(address,uint256,bytes)"
    assert probe["selector"] == "0xb61d27f6"
    assert "cast call" in probe["cast_call"]
    assert "execute(address,uint256,bytes)" in probe["cast_call"]


def test_run_bytecode_probes_writes_plan_and_foundry_harness(tmp_path):
    result = run_bytecode_probes(
        bytecode_meta=_delegatecall_executor_meta(),
        out_dir=tmp_path,
        address="0x1111111111111111111111111111111111111111",
        chain="ethereum",
    )

    assert result.status == "ok"
    assert result.meta["probe_count"] == 1
    assert (tmp_path / "probe_plan.json").exists()
    assert (tmp_path / "BYTECODE_PROBES.md").exists()
    harness = tmp_path / "foundry" / "test" / "BytecodeSelectorProbes.t.sol"
    assert harness.exists()
    text = harness.read_text(encoding="utf-8")
    assert "BytecodeSelectorProbes" in text
    assert 'abi.encodeWithSignature("execute(address,uint256,bytes)"' in text


def test_run_bytecode_probes_skips_when_no_risks(tmp_path):
    meta = analyze_bytecode("0x60016000", source_verified=False)

    result = run_bytecode_probes(bytecode_meta=meta, out_dir=tmp_path)

    assert result.status == "skipped"
    assert "no bytecode risk signals" in result.summary
