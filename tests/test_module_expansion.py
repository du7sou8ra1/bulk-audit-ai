"""Module/facet source expansion (v0.5): Diamond loupe + Euler module dispatcher,
with an Etherscan eth_call fallback when no node RPC is available. Pure logic, no network."""
from backend.core.source_fetcher import (
    SourcePackage, _decode_address, _decode_address_array, _selector,
    discover_facet_module_addresses, expand_module_sources,
)

FACET_A = "0x1111111111111111111111111111111111111111"
FACET_B = "0x2222222222222222222222222222222222222222"
SEL_FACETS = _selector("facetAddresses()")
SEL_MODIMPL = _selector("moduleIdToImplementation(uint256)")


def _addr_word(a): return a.lower().replace("0x", "").rjust(64, "0")
def _word(n): return f"{n:064x}"
def _enc_addr_array(addrs):
    out = _word(32) + _word(len(addrs))
    for a in addrs: out += _addr_word(a)
    return "0x" + out


class FakeOnchain:
    available = True
    def __init__(self, table): self.table = table
    def eth_call_raw(self, to, data): return self.table.get(data)


class Down:
    available = False


def _none(*a, **k): return None


def test_decode_address_array_roundtrip():
    assert [g.lower() for g in _decode_address_array(_enc_addr_array([FACET_A, FACET_B]))] == [FACET_A, FACET_B]


def test_decode_single_address():
    assert (_decode_address("0x" + _addr_word(FACET_A)) or "").lower() == FACET_A


def test_discover_via_node_rpc():
    oc = FakeOnchain({SEL_FACETS: _enc_addr_array([FACET_A, FACET_B])})
    addrs = [a.lower() for a in discover_facet_module_addresses(oc, "0xdiamond", eth_call=_none)]
    assert FACET_A in addrs and FACET_B in addrs


def test_discover_via_etherscan_fallback_when_rpc_down():
    table = {SEL_FACETS: _enc_addr_array([FACET_A]), SEL_MODIMPL + _word(500000): "0x" + _addr_word(FACET_B)}
    ec = lambda to, data, chain="ethereum": table.get(data)
    addrs = [a.lower() for a in discover_facet_module_addresses(Down(), "0xeuler", eth_call=ec)]
    assert FACET_A in addrs and FACET_B in addrs


def test_expand_merges_verified_module_source():
    table = {SEL_FACETS: _enc_addr_array([FACET_A])}
    ec = lambda to, data, chain="ethereum": table.get(data)
    def fake_fetch(addr, chain="ethereum"):
        return SourcePackage(address=addr, verified=True,
                             source_files={"EToken.sol": "contract EToken { function donateToReserves() external {} }"})
    merged, expanded = expand_module_sources(Down(), "0xeuler", "ethereum", None, fetch=fake_fetch, eth_call=ec)
    assert [e.lower() for e in expanded] == [FACET_A]
    assert any(k.startswith(f"_modules/{FACET_A.lower()}/") for k in merged)


def test_no_expansion_when_no_rpc_and_no_explorer():
    merged, expanded = expand_module_sources(Down(), "0xabc", fetch=lambda a, c="ethereum": None, eth_call=_none)
    assert merged == {} and expanded == []


def test_write_source_to_workspace_persists_compiler_metadata(tmp_path):
    from backend.core.source_fetcher import write_source_to_workspace

    pkg = SourcePackage(
        address="0xabc",
        verified=True,
        contract_name="C",
        source_files={"C.sol": "contract C {}"},
        compiler_metadata={
            "output": {
                "storageLayout": {
                    "storage": [{"label": "owner", "slot": "0", "offset": 0, "type": "t_address"}]
                }
            }
        },
    )

    write_source_to_workspace(tmp_path / "source", pkg)
    assert (tmp_path / "source" / "metadata.json").exists()
    assert "storageLayout" in (tmp_path / "source" / "metadata.json").read_text(encoding="utf-8")
