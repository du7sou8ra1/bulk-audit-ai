from backend.core.onchain import OnchainClient


class _FakeOnchain(OnchainClient):
    def __init__(self, *, available=True, native=0.0, calls=None):
        self.chain = "ethereum"
        self.rpc_url = "fake"
        self._available = available
        self.native = native
        self.calls = calls or {}

    @property
    def available(self):
        return self._available

    @staticmethod
    def checksum(address: str) -> str:
        return address

    def get_balance_eth(self, address: str):
        return self.native

    def call_typed(self, address, signature, arg_types=None, args=None, return_types=None):
        key = (address.lower(), signature)
        if key in self.calls:
            return self.calls[key]
        return self.calls.get(signature)


def test_value_context_unknown_never_claims_inert_when_rpc_unavailable():
    ctx = _FakeOnchain(available=False).probe_value_context("0xabc", referenced_by=[])
    assert ctx["state"] == "unknown"
    assert ctx["signal"] == "unknown"


def test_value_context_has_value_from_declared_asset_balance():
    asset = "0x1000000000000000000000000000000000000000"
    chain = _FakeOnchain(
        calls={
            "asset()": asset,
            (asset.lower(), "balanceOf(address)"): 123,
        }
    )
    ctx = chain.probe_value_context("0xabc")
    assert ctx["state"] == "has_value"
    assert ctx["signal"] == "self_holds_value"
    assert ctx["self_asset_balances"][0]["balance"] == 123


def test_value_context_flow_through_is_no_value_but_not_inert():
    src = "contract R { function swap(uint a) external { token.transferFrom(msg.sender,address(this),a); token.transfer(msg.sender,a); } }"
    ctx = _FakeOnchain().probe_value_context("0xabc", source_text=src, referenced_by=[])
    assert ctx["state"] == "no_value"
    assert ctx["signal"] == "value_flows_through"


def test_value_context_inert_requires_known_empty_reference_set():
    chain = _FakeOnchain()
    unknown_refs = chain.probe_value_context("0xabc", referenced_by=None)
    inert = chain.probe_value_context("0xabc", referenced_by=[])
    assert unknown_refs["state"] == "no_value"
    assert unknown_refs["signal"] == "unknown"
    assert inert["state"] == "no_value"
    assert inert["signal"] == "inert_unreferenced"


def test_value_context_dependents_require_reference_or_dependency_hint():
    ctx = _FakeOnchain().probe_value_context(
        "0xabc",
        contract_name="VaultImplementation",
        referenced_by=None,
    )
    assert ctx["state"] == "no_value"
    assert ctx["signal"] == "value_in_dependents"


def test_eth_call_raw_from_returns_unavailable_without_rpc():
    class NoRpc(OnchainClient):
        @property
        def w3(self):
            return None

    client = NoRpc(rpc_url="")
    result = client.eth_call_raw_from(
        "0x0000000000000000000000000000000000000001",
        "0x",
        "0x0000000000000000000000000000000000000002",
    )
    assert result == {"ok": None, "error": "rpc unavailable"}
