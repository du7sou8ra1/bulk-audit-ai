"""Tests for multi-chain support: chain-id mapping + per-chain RPC selection.
Run: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/test_multichain.py -q
"""
from backend.config import get_settings
from backend.core.onchain import OnchainClient


def test_etherscan_chain_ids():
    s = get_settings()
    assert s.etherscan_chain_id("base") == 8453
    assert s.etherscan_chain_id("scroll") == 534352
    assert s.etherscan_chain_id("zksync") == 324
    assert s.etherscan_chain_id("avalanche") == 43114
    assert s.etherscan_chain_id("unknown-chain") == 1  # safe default


def test_rpc_url_for_env_override(monkeypatch):
    s = get_settings()
    monkeypatch.setenv("RPC_URL_BASE", "https://base.example/rpc")
    assert s.rpc_url_for("base") == "https://base.example/rpc"
    # a chain with no override falls back to the default rpc_url
    assert s.rpc_url_for("optimism") == s.rpc_url


def test_onchain_client_uses_chain_rpc(monkeypatch):
    monkeypatch.setenv("RPC_URL_ARBITRUM", "https://arb.example/rpc")
    c = OnchainClient(chain="arbitrum")
    assert c.chain == "arbitrum"
    assert c.rpc_url == "https://arb.example/rpc"
