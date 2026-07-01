import json
from pathlib import Path

from backend.core.proxy_resolver import IMPL_SLOT, ProxyInfo
from backend.core.semantic_index import build_semantic_index
from backend.core.storage_layout import build_storage_layout, compact_storage_context, run_storage_layout
from backend.detectors.base import TargetContext


SRC = """
pragma solidity ^0.8.20;
contract VaultProxyLike {
    address public owner;
    address public priceOracle;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    bool public initialized;

    function initialize(address o) external { owner = o; initialized = true; }
    function setOracle(address next) external { priceOracle = next; }
    function deposit(uint256 amount) external { balances[msg.sender] += amount; totalSupply += amount; }
}
"""

MODULE_SRC = """
pragma solidity ^0.8.20;
contract Facet {
    address public owner;
    function exec(address target, bytes calldata data) external { target.delegatecall(data); }
}
"""


def _ctx() -> TargetContext:
    ctx = TargetContext(
        address="0x1111111111111111111111111111111111111111",
        chain="ethereum",
        profile="ultra-deep-v2",
        onchain=None,
        proxy_info=ProxyInfo(
            is_proxy=True,
            proxy_type="eip1967-transparent",
            implementation="0x2222222222222222222222222222222222222222",
            admin="0x3333333333333333333333333333333333333333",
            evidence={"slot_reads": {"implementation_value": "0x2222222222222222222222222222222222222222"}},
        ),
        workspace=Path("."),
        contract_name="VaultProxyLike",
        source_files={
            "VaultProxyLike.sol": SRC,
            "_modules/0x4444444444444444444444444444444444444444/Facet.sol": MODULE_SRC,
        },
        abi=[],
    )
    ctx.semantic = build_semantic_index(ctx.source_files, ctx.abi)
    ctx.protocol_graph = {
        "nodes": [
            {"role": "oracle", "label": "priceOracle", "address": "0x5555555555555555555555555555555555555555", "source": "state_var"}
        ]
    }
    return ctx


def test_storage_layout_marks_proxy_critical_slots_and_module_context():
    layout = build_storage_layout(_ctx())
    assert layout["schema"] == "bulk-audit-storage-layout/v1"
    assert any(row["slot"] == IMPL_SLOT for row in layout["proxy_slots"])
    families = {row["family"] for row in layout["critical_slots"]}
    assert {"authority", "initializer", "accounting", "cross_contract"} <= families
    assert any(row["kind"] == "proxy_storage" for row in layout["module_context"])
    assert any(row["kind"] == "module_source" for row in layout["module_context"])
    assert any(row["kind"] == "delegatecall" for row in layout["module_context"])
    assert any(row["role"] == "oracle" for row in layout["protocol_graph_links"])


def test_storage_layout_runner_writes_outputs_and_compact_context(tmp_path):
    res = run_storage_layout(_ctx(), tmp_path)
    assert res.status == "ok"


def test_storage_layout_uses_exact_compiler_build_info_slots(tmp_path):
    build_info = {
        "output": {
            "contracts": {
                "VaultProxyLike.sol": {
                    "VaultProxyLike": {
                        "storageLayout": {
                            "storage": [
                                {"label": "owner", "slot": "7", "offset": 0, "type": "t_address"},
                                {"label": "priceOracle", "slot": "8", "offset": 0, "type": "t_address"},
                                {"label": "balances", "slot": "9", "offset": 0, "type": "t_mapping"},
                            ],
                            "types": {
                                "t_address": {"label": "address", "numberOfBytes": "20"},
                                "t_mapping": {"label": "mapping(address => uint256)", "numberOfBytes": "32"},
                            },
                        }
                    }
                }
            }
        }
    }
    build_dir = tmp_path / "out" / "build-info"
    build_dir.mkdir(parents=True)
    (build_dir / "build.json").write_text(json.dumps(build_info), encoding="utf-8")

    ctx = _ctx()
    ctx.workspace = tmp_path
    layout = build_storage_layout(ctx)

    assert layout["summary"]["has_exact_storage_layout"] is True
    assert layout["summary"]["exact_storage_contract"] == "VaultProxyLike"
    by_name = {row["name"]: row for row in layout["declared_slots"]}
    assert by_name["owner"]["slot"] == 7
    assert by_name["owner"]["slot_exact"] is True
    assert by_name["priceOracle"]["storage_type_label"] == "address"
    compact = compact_storage_context(layout)
    assert compact["exact_storage_layout"]["available"] is True
    assert compact["exact_storage_layout"]["storage"][0]["label"] == "owner"
