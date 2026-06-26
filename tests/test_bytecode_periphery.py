from backend.core.bytecode_intel import _selector, analyze_bytecode
from backend.core.bytecode_probes import build_probe_plan
from backend.detectors.base import TargetContext
from backend.detectors.bytecode_periphery import BytecodePeripheryDetector


def _ctx(bytecode: str, *, source_verified=False, meta=None, probe_meta=None):
    tool_outputs = {}
    if meta:
        tool_outputs["bytecode-intel"] = {"meta": meta}
    if probe_meta:
        tool_outputs["bytecode-probes"] = {"meta": probe_meta}
    return TargetContext(
        address="0xabc",
        chain="ethereum",
        profile="ultra-deep-v2",
        onchain=None,
        proxy_info=None,
        workspace=None,
        contract_name="",
        source_files={"Verified.sol": "contract Verified {}"} if source_verified else {},
        bytecode=bytecode,
        tool_outputs=tool_outputs,
    )


def test_bytecode_periphery_promotes_closed_source_delegatecall_executor():
    bytecode = "0x63" + _selector("execute(address,uint256,bytes)") + "1457f4"
    meta = analyze_bytecode(bytecode, source_verified=False)

    findings = BytecodePeripheryDetector().run(_ctx(bytecode, meta=meta))

    assert len(findings) == 1
    assert findings[0].detector == "bytecode_periphery"
    assert findings[0].impact_score == 9.0
    assert findings[0].evidence["rule_id"] == "closed_source_delegatecall_executor"
    assert findings[0].evidence["bytecode_intel"]["selector_clusters"]["arbitrary_execution"]


def test_bytecode_periphery_attaches_phase7_probe_plan():
    bytecode = "0x63" + _selector("execute(address,uint256,bytes)") + "1457f4"
    meta = analyze_bytecode(
        bytecode,
        address="0x1111111111111111111111111111111111111111",
        chain="ethereum",
        source_verified=False,
    )
    probe_meta = build_probe_plan(meta)
    probe_meta["artifact_paths"] = {
        "foundry_harness": "/tmp/BytecodeSelectorProbes.t.sol",
    }

    findings = BytecodePeripheryDetector().run(_ctx(bytecode, meta=meta, probe_meta=probe_meta))

    probe_plan = findings[0].evidence["bytecode_probe_plan"]
    assert probe_plan["probe_count"] == 1
    assert probe_plan["probes"][0]["signature"] == "execute(address,uint256,bytes)"
    assert "cast call" in probe_plan["probes"][0]["cast_call"]
    assert any("BytecodeSelectorProbes" in step for step in findings[0].next_tests)


def test_bytecode_periphery_keeps_verified_source_noise_low():
    bytecode = "0x63" + _selector("transferFrom(address,address,uint256)") + "14f1"
    meta = analyze_bytecode(bytecode, source_verified=True)

    findings = BytecodePeripheryDetector().run(
        _ctx(bytecode, source_verified=True, meta=meta)
    )

    assert findings == []
