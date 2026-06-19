"""Fork-based oracle / flash-loan manipulation simulator (v0.5).

Turns `oracle_manipulation` CANDIDATES into CONFIRMATIONS where it can be done
honestly and automatically:

  * DONATION / balanceOf-manipulation (Venus exchange-rate, ERC4626 inflation,
    BlindBox): on a local fork, read the protocol's reported price/share value,
    inflate the target's underlying-token balance (simulating an unprivileged
    donation, via a self-contained storage-slot finder — no forge-std needed),
    re-read the price, and assert it MOVED. A price that moves from a pure
    donation is unprivileged-manipulable -> CONFIRMED. A price that doesn't move
    (oracle/internal-accounting based) -> the candidate is refuted by simulation.

  * AMM-spot flash-loan: needs the specific pool + attack sequence, which can't be
    auto-generated safely, so this emits a runnable Aave-v3 flash-loan SCAFFOLD
    with the invariant assertion pre-written (never auto-counted as passing).

SAFETY: identical guarantees to poc_generator — local `forge test --fork-url`
only, ffi disabled, no broadcast/keys (the foundry_runner refuses those tokens).
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..detectors.base import FindingCandidate, TargetContext

logger = logging.getLogger("bulkauditai.flashloan_sim")

_PRICE_NAME_HINTS = (
    "price", "share", "rate", "totalassets", "pricepershare", "convertto",
    "exchangerate", "getrate", "lastprice", "spotprice", "value", "getamountout",
)
_TOKEN_GETTERS = ("asset()", "token()", "underlying()", "want()", "stable()",
                  "collateral()", "baseToken()", "wantToken()")

CHEAT_ADDR = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"


def is_sim_eligible(candidate: FindingCandidate) -> bool:
    return str((candidate.evidence or {}).get("bug_class", "")) == "oracle"


def _pick_price_view(ctx: TargetContext) -> str | None:
    """A zero-arg view function returning a single uint — the 'reported price'."""
    abi = ctx.abi
    if not isinstance(abi, list):
        return None
    best = None
    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        if item.get("stateMutability") not in ("view", "pure"):
            continue
        if item.get("inputs"):  # must be callable with no args
            continue
        outs = item.get("outputs") or []
        if len(outs) != 1 or not str(outs[0].get("type", "")).startswith("uint"):
            continue
        name = item.get("name", "")
        low = name.lower()
        if any(h in low for h in _PRICE_NAME_HINTS):
            return name  # strong name match wins immediately
        best = best or name
    return best


def _find_underlying_token(ctx: TargetContext) -> str | None:
    oc = ctx.onchain
    if oc is None:
        return None
    for getter in _TOKEN_GETTERS:
        try:
            addr = oc.try_address_getter(ctx.address, getter)
        except Exception:  # noqa: BLE001
            addr = None
        if addr:
            return addr
    return None


def _foundry_toml() -> str:
    return ("[profile.default]\nsrc='src'\nout='out'\ntest='test'\nlibs=[]\n"
            "ffi=false\nfs_permissions=[]\n")


_DONATION_PROBE = """// SPDX-License-Identifier: MIT
// AUTO-GENERATED ORACLE-MANIPULATION FORK PROBE — local fork only. DO NOT BROADCAST.
// PASSES iff an unprivileged token donation moves the protocol's reported price.
pragma solidity ^0.8.19;

interface Vm {
    function load(address,bytes32) external view returns (bytes32);
    function store(address,bytes32,bytes32) external;
}
interface IERC20 { function balanceOf(address) external view returns (uint256); }
interface IPriced { function __PRICE_FN__() external view returns (uint256); }

contract OracleManipProbe {
    Vm constant vm = Vm(__CHEAT__);
    address constant TARGET = __TARGET__;
    address constant TOKEN  = __TOKEN__;

    function test_donation_moves_reported_price() external {
        uint256 priceBefore = IPriced(TARGET).__PRICE_FN__();
        uint256 bal = IERC20(TOKEN).balanceOf(TARGET);
        uint256 donation = bal == 0 ? 1e24 : bal * 2;       // simulate an attacker donation
        require(_setBalance(TOKEN, TARGET, bal + donation), "balance slot not found");
        uint256 priceAfter = IPriced(TARGET).__PRICE_FN__();
        // If a PURE donation changes the reported price, it is unprivileged-manipulable.
        require(priceAfter != priceBefore,
            "price not balance-sensitive: donation did not move it (likely oracle/internal-accounting)");
    }

    // Self-contained storage `deal` (forge-std stdstore, inlined): brute-force the
    // ERC20 balance mapping slot, write the new balance, verify via balanceOf.
    function _setBalance(address token, address who, uint256 amount) internal returns (bool) {
        for (uint256 slot = 0; slot < 40; slot++) {
            bytes32 key = keccak256(abi.encode(who, slot));
            bytes32 prev = vm.load(token, key);
            vm.store(token, key, bytes32(amount));
            if (IERC20(token).balanceOf(who) == amount) return true;
            vm.store(token, key, prev); // restore and keep searching
        }
        return false;
    }
}
"""

_FLASHLOAN_SCAFFOLD = """// SPDX-License-Identifier: MIT
// AUTO-GENERATED FLASH-LOAN SCAFFOLD — local fork only. DO NOT BROADCAST.
// Spot-AMM manipulation needs the specific pool + attack sequence; complete the
// 2 TODO blocks. Never auto-counted as a passing PoC.
pragma solidity ^0.8.19;

interface Vm { function createSelectFork(string calldata) external returns (uint256); }
interface IAavePool {
    function flashLoanSimple(address receiver, address asset, uint256 amount,
        bytes calldata params, uint16 referralCode) external;
}
interface IPriced { function __PRICE_FN__() external view returns (uint256); }

contract FlashLoanProbe {
    address constant TARGET = __TARGET__;
    // Aave v3 Pool (mainnet). Swap for the right lender/chain.
    IAavePool constant POOL = IAavePool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);

    function executeOperation(address asset, uint256 amount, uint256 premium,
        address, bytes calldata) external returns (bool) {
        uint256 priceBefore = IPriced(TARGET).__PRICE_FN__();
        // TODO 1: use `amount` to skew the AMM pool the target prices against.
        // TODO 2: call the target's profit path (borrow/mint/redeem) at the skewed price.
        uint256 priceAfter = IPriced(TARGET).__PRICE_FN__();
        require(priceAfter != priceBefore, "spot price unaffected");
        // repay handled by approving amount+premium to POOL.
        return true;
    }

    function test_flashloan_attack() external {
        // TODO: POOL.flashLoanSimple(address(this), <asset>, <amount>, "", 0);
        // then assert attacker profit > 0.
    }
}
"""


def build_donation_probe(target: str, token: str, price_fn: str) -> str:
    return (_DONATION_PROBE
            .replace("__CHEAT__", CHEAT_ADDR)
            .replace("__TARGET__", target)
            .replace("__TOKEN__", token)
            .replace("__PRICE_FN__", price_fn))


def build_flashloan_scaffold(target: str, price_fn: str | None) -> str:
    return (_FLASHLOAN_SCAFFOLD
            .replace("__TARGET__", target)
            .replace("__PRICE_FN__", price_fn or "pricePerShare"))


def generate_and_run(
    ctx: TargetContext,
    candidate: FindingCandidate,
    sim_dir: Path,
    *,
    rpc_url: str,
    timeout: int,
) -> dict:
    """Build + run the manipulation probe. Returns a result dict.

    ``manipulable`` is True only when forge confirms the donation moved the price.
    """
    price_fn = _pick_price_view(ctx)
    token = _find_underlying_token(ctx)

    sim_dir.mkdir(parents=True, exist_ok=True)
    (sim_dir / "foundry.toml").write_text(_foundry_toml(), encoding="utf-8")
    (sim_dir / "test").mkdir(parents=True, exist_ok=True)
    (sim_dir / "src").mkdir(parents=True, exist_ok=True)

    # If we can't identify a zero-arg price view AND an underlying token, we can't
    # auto-confirm — emit the flash-loan scaffold instead and be honest.
    if not price_fn or not token:
        src = build_flashloan_scaffold(ctx.address, price_fn)
        (sim_dir / "test" / "FlashLoanProbe.t.sol").write_text(src, encoding="utf-8")
        return {"generated": False, "manipulable": None, "scaffold": True,
                "note": f"scaffold only (price_view={price_fn}, token={token}); "
                        "complete the flash-loan TODO blocks to confirm"}

    from ..runners.foundry_runner import run_forge_tests

    src = build_donation_probe(ctx.address, token, price_fn)
    test_path = sim_dir / "test" / "OracleManipProbe.t.sol"
    test_path.write_text(src, encoding="utf-8")

    runner = run_forge_tests(
        sim_dir, sim_dir / "out_logs", rpc_url=rpc_url, timeout=timeout,
        match_path="test/OracleManipProbe.t.sol",
    )
    manipulable = runner.status == "ok" and runner.meta.get("tests_run", 0) >= 1
    note = (
        f"CONFIRMED: a donation to {ctx.address} moved {price_fn}() — unprivileged "
        "price manipulation"
        if manipulable else
        f"not confirmed: {price_fn}() did not move from a donation (likely oracle/"
        "internal-accounting based) or slot not found"
    )
    return {"generated": True, "manipulable": manipulable, "price_fn": price_fn,
            "token": token, "runner": runner, "runner_status": runner.status, "note": note}
