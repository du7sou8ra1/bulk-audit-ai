# Validation corpus

Labeled contract addresses for measuring the tool's **precision** (false-positive
rate) and **recall** against ground truth. Two harnesses consume this:

- **Recall** — `backend/core/exploit_benchmark.py` (known-exploited contracts must
  still fire the expected detectors).
- **Precision** — `backend/core/precision_benchmark.py` (known-safe / not-deployed
  addresses must produce **zero reportable findings**).

## Offline precision gate (no keys needed)

Runs the deterministic pipeline (detectors → candidate_sanity → dedup → scoring)
on inline safe-code fixtures and asserts zero reportable findings:

```bash
venv/Scripts/python -m pytest tests/test_precision_benchmark.py -q
```

## Live precision run (on the VPS, with keys)

The high-value check: point the tool at real addresses that you have *verified* are
false positives (e.g. the batch-130 audit set) and confirm the tool now stays
silent. Set the **correct per-chain RPC** first — this is the batch-130 root cause:

```bash
# Without RPC_URL_BASE, a Base scan silently reads MAINNET and misattributes
# L1 token bytecode to Base. Always set the chain's own RPC.
export RPC_URL_BASE=https://mainnet.base.org        # or your provider
export ETHERSCAN_API_KEY=...
```

Then scan the corpus addresses (normal pipeline) and confirm no OPEN reportable
findings remain. The chain-attribution gate (`candidate_sanity._target_attribution_reason`)
now auto-suppresses:
- addresses with **no code on the scanned chain** (`eth_getCode == 0x`), and
- any target when the **RPC's chainid ≠ the scanned chain** (misconfig guard).

## Corpus format

`*_precision_corpus.json` — a JSON array; `label` in `{safe, not_deployed}` means
the address MUST NOT yield a reportable finding:

```json
[
  {"id": "aave-l1-on-base", "name": "AAVE token (L1) scanned on Base",
   "chain": "base", "address": "0x...", "label": "not_deployed",
   "reason": "L1-only token; no code on Base -> any finding is misattributed"}
]
```

Populate `base_precision_corpus.json` with your verified batch-130 false-positive
addresses (the L1 token addresses that had no code on Base) to lock them in as a
regression gate. Load with `precision_benchmark.load_precision_corpus(path)`.
