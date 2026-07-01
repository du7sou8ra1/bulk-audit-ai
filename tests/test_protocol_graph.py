import json
from pathlib import Path

from backend.core.protocol_graph import (
    build_protocol_graph,
    build_scan_protocol_graph,
    run_protocol_graph,
    select_companion_scan_targets,
)
from backend.core.semantic_index import build_semantic_index
from backend.detectors.base import TargetContext
from backend.detectors.economic_oracle_lending import EconomicOracleLendingDetector
from backend.core.proxy_resolver import ProxyInfo


_COMPOUND_FLOW = """
pragma solidity ^0.8.0;
interface ICToken { function borrow(uint256 amount) external returns (uint256); }
interface IComptroller { function getAccountLiquidity(address account) external view returns (uint256, uint256, uint256); }
contract CompoundBorrowFlow {
  IComptroller public comptroller;
  Oracle public oracle;
  ICToken public cUniToken;
  address public asset;
  function leveredBorrow(address market) external {
    (, uint256 liquidity,) = comptroller.getAccountLiquidity(msg.sender);
    uint256 price = oracle.getUnderlyingPrice(market);
    uint256 maxBorrow = liquidity / price;
    cUniToken.borrow(maxBorrow);
  }
}
"""


def _ctx(src: str = _COMPOUND_FLOW) -> TargetContext:
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
        ),
        workspace=Path("."),
        contract_name="CompoundBorrowFlow",
        source_files={"CompoundBorrowFlow.sol": src},
        abi=[],
    )
    ctx.semantic = build_semantic_index(ctx.source_files, ctx.abi)
    return ctx


def test_protocol_graph_infers_lending_oracle_surface_and_companions():
    graph = build_protocol_graph(_ctx())
    roles = {node.get("role") for node in graph["nodes"]}
    assert "oracle" in roles
    assert "lending_controller" in roles
    assert "lending_market" in roles
    assert "strategy" in roles  # proxy implementation
    assert "oracle_lending" in {surface["id"] for surface in graph["surfaces"]}
    assert any(edge["kind"] == "reads_price_or_rate" for edge in graph["edges"])
    assert any(c["role"] == "oracle" and c["unresolved"] is True for c in graph["companion_scan_candidates"])


def test_protocol_graph_runner_writes_json_and_markdown(tmp_path):
    ctx = _ctx()
    res = run_protocol_graph(ctx, tmp_path)
    assert res.status == "ok"
    assert res.meta["summary"]["surface_count"] >= 1
    assert Path(res.json_output_path).exists()
    assert (tmp_path / "protocol_graph.md").exists()
    saved = json.loads(Path(res.json_output_path).read_text(encoding="utf-8"))
    assert saved["schema"] == "bulk-audit-protocol-graph/v1"


def test_scan_protocol_graph_merge_marks_already_scanned_candidate(tmp_path):
    g1 = build_protocol_graph(_ctx())
    g1["companion_scan_candidates"].append({
        "role": "oracle",
        "label": "oracle",
        "address": "0x4444444444444444444444444444444444444444",
        "source": "test",
        "unresolved": False,
    })
    g2 = build_protocol_graph(_ctx("contract Oracle { function getUnderlyingPrice(address) external view returns(uint256){ return 1; } }"))
    g2["target"]["address"] = "0x4444444444444444444444444444444444444444"
    d1 = tmp_path / g1["target"]["address"].lower()
    d2 = tmp_path / g2["target"]["address"].lower()
    d1.mkdir()
    d2.mkdir()
    (d1 / "protocol_graph.json").write_text(json.dumps(g1), encoding="utf-8")
    (d2 / "protocol_graph.json").write_text(json.dumps(g2), encoding="utf-8")

    merged = build_scan_protocol_graph(99, tmp_path)
    assert merged["summary"]["target_graph_count"] == 2
    assert merged["summary"]["surface_count"] >= 1
    assert any(c.get("already_in_scan") for c in merged["companion_scan_candidates"])


def test_select_companion_scan_targets_filters_noise_and_prioritizes_roles(tmp_path):
    scan_graph = {
        "schema": "bulk-audit-scan-protocol-graph/v1",
        "companion_scan_candidates": [
            {"role": "asset", "label": "usdc", "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "unresolved": False},
            {"role": "lending_controller", "label": "comptroller", "address": "0xcccccccccccccccccccccccccccccccccccccccc", "unresolved": False},
            {"role": "oracle", "label": "priceOracle", "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "unresolved": False, "confidence": 0.5},
            {"role": "verifier", "label": "verifier", "unresolved": True},
            {"role": "amm_pair", "label": "pair", "address": "0xdddddddddddddddddddddddddddddddddddddddd", "unresolved": False, "confidence": 0.9},
            {"role": "strategy", "label": "strategy", "address": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "unresolved": False},
        ],
    }
    (tmp_path / "protocol_graph.json").write_text(json.dumps(scan_graph), encoding="utf-8")

    selected = select_companion_scan_targets(
        tmp_path,
        existing_addresses={"0xcccccccccccccccccccccccccccccccccccccccc"},
        max_new=2,
    )

    assert [row["role"] for row in selected] == ["oracle", "amm_pair"]
    assert [row["address"].lower() for row in selected] == [
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xdddddddddddddddddddddddddddddddddddddddd",
    ]


def test_economic_detector_evidence_includes_protocol_graph_context():
    ctx = _ctx()
    ctx.protocol_graph = build_protocol_graph(ctx)
    findings = EconomicOracleLendingDetector().run(ctx)
    assert findings
    assert any((f.evidence.get("protocol_graph") or {}).get("surfaces") for f in findings)
