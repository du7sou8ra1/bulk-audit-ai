"""Chain-attribution FP gate (batch-130 root cause #1).

A Base scan whose RPC falls back to mainnet (RPC_URL_BASE unset) reads L1 bytecode
for L1-only token addresses and pins it to empty Base addresses -> 100% false
positives. Two definitive gates: RPC chain mismatch, and codeless target on the
correctly-scoped chain. Unknown (no/failed RPC) must NEVER suppress.

Run: venv/Scripts/python -m pytest tests/test_chain_attribution.py -q
"""
from pathlib import Path

from backend.core.candidate_sanity import apply_candidate_sanity
from backend.core.onchain import OnchainClient
from backend.detectors.base import FindingCandidate, TargetContext


class _ProxyInfo:
    admin_owner = None
    owner = None
    admin = None
    implementation = None


def _ctx(onchain, *, chain="base") -> TargetContext:
    return TargetContext(
        address="0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9",  # AAVE on L1, no code on Base
        chain=chain,
        profile="ultra-deep-v2",
        onchain=onchain,
        proxy_info=_ProxyInfo(),
        workspace=Path("."),
        contract_name="Target",
        source_files={"Target.sol": "contract Target { function initialize(address o) external { owner = o; } address owner; }"},
    )


def _cand() -> FindingCandidate:
    return FindingCandidate(
        detector="unprotected_initializer",
        title="Public initializer writes a privilege slot with no guard: initialize",
        description="test",
        impact_score=9.0,
        confidence_score=8.0,
        evidence={"function": "initialize",
                  "attacker_control_binding": {"variable": "o", "role": "destination"}},
        affected_functions=["initialize"],
    )


class _NoChain:
    available = False


class _CodelessChain:
    available = True
    expected_chain_id = 8453

    def chain_mismatch(self):
        return False

    def live_chain_id(self):
        return 8453

    def get_code(self, _addr):
        return "0x"


class _WrongChain:
    """RPC connected but reporting mainnet (chainid 1) while we scan Base (8453)."""
    available = True
    expected_chain_id = 8453

    def chain_mismatch(self):
        return True

    def live_chain_id(self):
        return 1

    def get_code(self, _addr):
        return "0x60806040deadbeef"  # non-empty: it's the WRONG chain's bytecode


class _LiveCodedChain:
    available = True
    expected_chain_id = 8453

    def chain_mismatch(self):
        return False

    def live_chain_id(self):
        return 8453

    def get_code(self, _addr):
        return "0x60806040feedface"


class _RpcFailChain:
    available = True
    expected_chain_id = 8453

    def chain_mismatch(self):
        return None  # read failed -> unknown

    def live_chain_id(self):
        return None

    def get_code(self, _addr):
        return None  # read failed -> unknown


# ---- the gate ----
def test_codeless_target_suppresses_all_candidates():
    ctx = _ctx(_CodelessChain())
    cands = [_cand(), _cand()]
    assert apply_candidate_sanity(ctx, cands) == 2
    assert all(c.evidence["suppressed"] for c in cands)
    assert "no contract code" in cands[0].evidence["suppressed_reason"]
    assert cands[0].evidence["refutation_pattern_class"] == "chain_misattribution"


def test_wrong_chain_rpc_suppresses_all_candidates():
    ctx = _ctx(_WrongChain())
    cands = [_cand()]
    assert apply_candidate_sanity(ctx, cands) == 1
    assert cands[0].evidence["suppressed"] is True
    assert "chain mismatch" in cands[0].evidence["suppressed_reason"].lower()


def test_live_coded_target_is_not_chain_suppressed():
    # Real code on the correct chain + a genuine structural bug -> must survive.
    ctx = _ctx(_LiveCodedChain())
    cand = _cand()
    assert apply_candidate_sanity(ctx, [cand]) == 0
    assert not cand.evidence.get("suppressed")


def test_rpc_failure_is_unknown_never_suppresses():
    ctx = _ctx(_RpcFailChain())
    cand = _cand()
    assert apply_candidate_sanity(ctx, [cand]) == 0
    assert not cand.evidence.get("suppressed")


def test_no_rpc_client_never_suppresses():
    ctx = _ctx(_NoChain())
    cand = _cand()
    assert apply_candidate_sanity(ctx, [cand]) == 0
    assert not cand.evidence.get("suppressed")


def test_chain_gate_can_be_disabled():
    ctx = _ctx(_CodelessChain())
    cand = _cand()
    # With the gate off, the codeless target is NOT auto-suppressed by this pass.
    assert apply_candidate_sanity(ctx, [cand], enable_chain_gate=False) == 0
    assert not cand.evidence.get("suppressed")


class _RaisingGetCode:
    """Available RPC that would raise if get_code is called — proves the gate uses
    ctx.bytecode (already fetched by the scanner) instead of re-reading."""
    available = True
    expected_chain_id = 8453

    def chain_mismatch(self):
        return False

    def get_code(self, _addr):
        raise AssertionError("get_code must not be called when ctx.bytecode is present")


def test_gate_reuses_ctx_bytecode_and_skips_redundant_read():
    ctx = _ctx(_RaisingGetCode())
    ctx.bytecode = "0x"  # scanner already saw an empty (codeless) target
    cand = _cand()
    assert apply_candidate_sanity(ctx, [cand]) == 1
    assert "no contract code" in cand.evidence["suppressed_reason"]


def test_ctx_bytecode_present_overrides_stale_empty_read():
    ctx = _ctx(_CodelessChain())   # its get_code would say "0x"
    ctx.bytecode = "0x60806040feedface"  # but the scan fetched real code
    cand = _cand()
    # ctx.bytecode is authoritative -> not codeless -> not chain-suppressed.
    assert apply_candidate_sanity(ctx, [cand]) == 0
    assert not cand.evidence.get("suppressed")


# ---- OnchainClient.chain_mismatch logic ----
class _FakeEth:
    def __init__(self, cid):
        self.chain_id = cid


class _FakeW3:
    def __init__(self, cid):
        self.eth = _FakeEth(cid)

    def is_connected(self):
        return True


def test_onchain_chain_mismatch_true_on_mainnet_fallback():
    oc = OnchainClient(chain="base")
    oc._w3 = _FakeW3(1)  # node reports mainnet
    assert oc.expected_chain_id == 8453
    assert oc.live_chain_id() == 1
    assert oc.chain_mismatch() is True


def test_onchain_chain_match_when_correct():
    oc = OnchainClient(chain="base")
    oc._w3 = _FakeW3(8453)
    assert oc.chain_mismatch() is False


def test_onchain_chain_mismatch_unknown_without_rpc():
    oc = OnchainClient(chain="base")
    oc._w3 = None
    assert oc.live_chain_id() is None
    assert oc.chain_mismatch() is None


# ---- scan-start chain preflight ----
def test_chain_preflight_warns_on_wrong_chain():
    from backend.core.scanner import chain_preflight_warning
    msg = chain_preflight_warning("base", _WrongChain())
    assert msg is not None
    assert "CHAIN MISMATCH" in msg and "RPC_URL_BASE" in msg
    assert "8453" in msg and "chainid 1" in msg


def test_chain_preflight_silent_when_correct():
    from backend.core.scanner import chain_preflight_warning
    assert chain_preflight_warning("base", _LiveCodedChain()) is None


def test_chain_preflight_silent_without_rpc():
    from backend.core.scanner import chain_preflight_warning
    assert chain_preflight_warning("base", _NoChain()) is None


def test_chain_preflight_silent_on_rpc_failure():
    from backend.core.scanner import chain_preflight_warning
    assert chain_preflight_warning("base", _RpcFailChain()) is None
