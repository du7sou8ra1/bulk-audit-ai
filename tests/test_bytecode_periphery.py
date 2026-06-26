from backend.core.bytecode_intel import _selector, analyze_bytecode
from backend.detectors.base import TargetContext
from backend.detectors.bytecode_periphery import BytecodePeripheryDetector


def _ctx(bytecode: str, *, source_verified=False, meta=None):
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
        tool_outputs={"bytecode-intel": {"meta": meta}} if meta else {},
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


def test_bytecode_periphery_keeps_verified_source_noise_low():
    bytecode = "0x63" + _selector("transferFrom(address,address,uint256)") + "14f1"
    meta = analyze_bytecode(bytecode, source_verified=True)

    findings = BytecodePeripheryDetector().run(
        _ctx(bytecode, source_verified=True, meta=meta)
    )

    assert findings == []
