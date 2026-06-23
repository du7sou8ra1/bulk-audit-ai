# Build backlog / ideas

Not yet implemented (owner: build later, batched). Recall is GOOD across test runs
(real bugs found: Lendf.me reentrancy, Rari interprocedural reentrancy, Pickle
"evil jar", Multichain permit). Everything below is precision / accuracy work.

## FP-reduction fixes (deferred 2026-06-22, from Lendf.me/Rari/Multichain/Pickle/Revest/Cover runs)

1. **access_control — recognize custom guard modifiers.**
   Today any external fn without a KNOWN access marker is flagged
   "no access control - likely critical". Misses custom modifiers:
   - Revest `onlyRevestController` -> 9 FPs on mint*/burn*/withdrawFNFT
   - Compound `mintAllowed`/`seizeVerify` (comptroller-gated internals) -> FPs
   Fix: treat `only*` / `*Only` / `require*Auth` / `restricted` / `*Guard` modifiers
   and `require(msg.sender == <storedAddr>)` as guards; bias internal `*Allowed`/
   `*Verify` callbacks to lower severity. (Biggest single win.)

2. **zk_verifier — stop the `*Verify` misfire.**
   Fired conf 10 "Confirmed critical" on Compound `mintFresh`/`redeemFresh` (no ZK
   present). Matches any `*Verify(`-style bare call. Fix: require real verifier/proof
   context (verifier var, proof bytes, pairing/precompile) before firing; skip
   ERC20/cToken mint/redeem.

3. **delegatecall — admin-set impl is NOT attacker-settable.**
   Fired conf 8 on Compound `delegateTo` / proxy `_delegate` where the target is the
   impl slot set by an admin-guarded setter. Fix: if the target is a storage var
   written only by an access-controlled setter (not a fn param), downgrade/skip.

4. **dedup across detectors.**
   Collapse multiple findings on the same (file, function): `initialize` x3,
   `mint` x2, `delegateTo` x2, etc.

## ZK / proof-binding

5. **proofData-value-not-bound should cover escapeHatch / forced-exit paths.**
   Aztec v1 RollupProcessor (0x737901...42A2ba) $2M Jun-17 drain went through
   `escapeHatch(bytes proofData, bytes signatures, bytes viewingKeys)`: the withdrawn
   amount/owner decoded from `bytes proofData` was not bound to the verifier's
   committed public inputs (verifier accepted the proof). The detector fired the RIGHT
   CLASS ("value extracted from proofData, no in-function hash-binding") but on
   `transferFee` (txFee), NOT escapeHatch, because the amount comes from `bytes` not a
   scalar param. Fix: flag permissionless forced-exit/escape paths that release
   value/owner decoded from `bytes proofData`.
   NOTE: root cause = circuit/verifier soundness = OUT of static scope (tool correctly
   says "engage a ZK auditor with the circuit repo"); the static lead is the ceiling.

## Reserved
- "ultra-deep" profile name -> reserved for the NEXT wave of NEW detectors.

## From the 2026-exploit-list test run (2026-06-23)

6. **hook_pair_burn_sync misses real deflationary tokens (SOF).**
   SOF (BSC 0xaeB414...08dF42, verified, 10 files) is a burn-before-sync reflection
   token; it references balanceOf(pair) and calls sync(). The dedicated
   hook_pair_burn_sync detector did NOT fire — only fot_swap_bounds (conf 5 on
   swapTokenForUsdt) flagged the area, and the AI then refuted it. Fix: make
   hook_pair_burn_sync match a token `_transfer`/burn that reduces the pair's balance
   (balanceOf(pair)) without an immediate pair.sync().

7. **AI classifier over-refutes to conf-2.0 "False positive".**
   The refuter stamps almost everything FALSE_POSITIVE @ conf 2.0, burying real leads
   (SOF fot_swap_bounds 5.0 -> 2.0). It is CORRECT on standard library code
   (PancakePair FPs), so the fix is to distinguish standard/audited code (kill) from
   project-specific economic leads (keep as NEEDS_INVESTIGATION). Tie into the
   confirmable-shield / cross-signal corroboration already in the codebase.

## Test-list hygiene (blocks testing; not a tool bug)
- Many "exploit" addresses point at the WRONG contract: TMM (0xc36C71...) resolved to
  the standard PancakePair (the pool), NOT the buggy token. The burn-without-sync bug
  is in the TOKEN -> need the vulnerable token/logic address.
- Movie (0xDf7eD2...) is NOT verified on BscScan -> no source -> untestable.
- Gemini research prompt must demand the VULNERABLE/verified contract (token or logic),
  never the pool/pair or an unverified address.

## NEW classes from the GitHub-research agent (2026-06-23) — implement as ULTRA-DEEP detectors
Sources: DeFiHackLabs, Code4rena/Sherlock/Solodit, BlockSec/SlowMist/CertiK/OZ/Verichains/DarkNavy.
13 classes confirmed distinct from the current 30.

TIER 1 (build first — crisp signature + verified 8-figure 2025/26 losses):
1. vault_share_donation_inflation — totalAssets=balanceOf(this) feeds shares=assets*supply/totalAssets;
   direct-transfer donation inflates share price, next depositor rounds to 0. Sonne ~$20M, Hundred, Onyx.
   Heuristic: taint balanceOf(address(this)) -> division by totalSupply with no internal _totalAssets
   accumulator and no virtual-offset/dead-shares.
2. liquidation_collateral_not_cleared — liquidate/close/withdraw transfers collateral but never zeroes the
   position slot (inputAmount/collateral/principal) read by later borrow/solvency. MIM/Abracadabra ~$12.9M (Mar25).
   Heuristic: in liquidat|close|withdraw|settle, collateral transfer with no delete/=0/-= on position slot before exit.
3. cross_chain_receiver_source_auth — lzReceive/_lzReceive/ccipReceive missing (a) msg.sender==endpoint AND
   (b) peer/trusted-remote (peers[srcEid] / sourceChainSelector+sender allowlist). KelpDAO ~$290M (Apr26).
4. arbitrary_from_transferFrom — transferFrom(from,...) where from is a param/decoded-calldata != msg.sender,
   redeeming a victim's standing approval. LI.FI ~$9-11.6M (Jul24); custom Uniswap router (Feb26).
5. directional_rounding_invariant — paired up/down scaling rounds the WRONG direction (over-credits user),
   flash-looped. Balancer V2 ~$125M (Nov25), Bunni ~$8.3M. (Cetus $223M is integer-OVERFLOW, not rounding.)

TIER 2 (near-syntactic): 6. eip1271_magic_value_spoof (GnosisPay ~$265K) — isValidSignature magic accepted with
success unchecked OR signer not authorized. 7. erc2771_msgsender_spoof — ERC2771Context + delegatecall Multicall
calldata-suffix forgery (thirdweb TIME). 8. reinitializable_proxy_delegatecall — unguarded initialize wiring a
delegatecall target (Renegade ~$209K, May26). 9. signed_unsigned_cast_mismatch — int->uint cast w/o x>=0 bypasses
minOut. 10. ecrecover_zero_address_bypass — ecrecover==signer w/o require(!=address(0)) (LegendaryMoneyMon).
11. payable_multicall_msgvalue_reuse — payable multicall delegatecall loop counts msg.value N times (MISO/Opyn).
12. decimals_precision_mismatch — hardcoded 1e18 vs variable decimals() (Kipseli ~$72K, Apr26).
13. batch_array_length_mismatch — parallel arrays iterated without length-equality require.

Lower priority: read_only_reentrancy_price (dForce/Sentiment — check interproc reentrancy+oracle first),
dn404_hybrid_ledger_desync, unbounded_loop_dos, unchecked_lowlevel_return (low-level call variant),
eip712_cross_domain_replay (immutable-cached-chainId sub-pattern), approve_race_not_zeroed.
CAVEATS: Cetus/Aftermath are Sui/Move (not EVM); Permit2 phishing is off-chain (exclude).
