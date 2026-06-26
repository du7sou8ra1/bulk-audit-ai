from backend.core.bytecode_intel import (
    _selector,
    analyze_bytecode,
    detect_minimal_proxy,
    run_bytecode_intel,
)


def test_bytecode_intel_extracts_executor_delegatecall_signal(tmp_path):
    execute = _selector("execute(address,uint256,bytes)")
    # PUSH4 execute.selector, EQ, JUMPI, DELEGATECALL
    bytecode = "0x63" + execute + "1457f4"

    report = analyze_bytecode(bytecode, address="0xabc", chain="ethereum")

    assert report["code_size_bytes"] == 8
    assert report["selector_clusters"]["arbitrary_execution"] == [
        "execute(address,uint256,bytes)"
    ]
    assert report["opcode_counts"]["DELEGATECALL"] == 1
    assert {
        signal["rule_id"] for signal in report["risk_signals"]
    } >= {"closed_source_delegatecall_executor"}


def test_bytecode_intel_detects_eip1167_minimal_proxy():
    impl = "1234567890abcdef1234567890abcdef12345678"
    runtime = (
        "363d3d373d3d3d363d73"
        + impl
        + "5af43d82803e903d91602b57fd5bf3"
    )

    assert detect_minimal_proxy(runtime) == "0x" + impl


def test_bytecode_intel_runner_writes_artifacts(tmp_path):
    bytecode = "0x63" + _selector("transferFrom(address,address,uint256)") + "14f1"

    result = run_bytecode_intel(bytecode=bytecode, out_dir=tmp_path)

    assert result.status == "ok"
    assert result.json_output_path
    assert result.stdout_path
    assert (tmp_path / "bytecode_intel.json").exists()
    assert (tmp_path / "disassembly.txt").exists()
    assert result.meta["selector_clusters"]["approval_spender"]


def test_bytecode_intel_skips_empty_runtime(tmp_path):
    result = run_bytecode_intel(bytecode="0x", out_dir=tmp_path)

    assert result.status == "skipped"
    assert "no deployed runtime bytecode" in result.summary
