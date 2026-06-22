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
