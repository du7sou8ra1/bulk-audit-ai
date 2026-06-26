# Elite Phase 6: Bytecode Intelligence Lane

Phase 6 adds a bytecode/decompiler-lite pass for targets where verified source
is missing, stale, incomplete, or only a proxy shell is available.

## What It Adds

- New `bytecode-intel` tool run, enabled by default through
  `ENABLE_BYTECODE_INTEL=true`.
- Runtime bytecode hashing before and after Solidity metadata stripping.
- EIP-1167 minimal proxy target extraction.
- PUSH4 selector extraction and known selector clustering.
- EIP-1967 slot constant detection.
- Risk-opcode counts for `DELEGATECALL`, `CALLCODE`, `SELFDESTRUCT`,
  `ORIGIN`, `EXTCODESIZE`, `CREATE2`, and related EVM edges.
- New Ultra Deep V2 detector: `bytecode_periphery`.

## Findings It Can Surface

- Closed-source delegatecall/executor clusters.
- Legacy `CALLCODE` runtime paths.
- `tx.origin` in mutable or external-call bytecode flows.
- Closed-source approval-spender/router clusters.
- Unverified upgrade/admin/proxy bytecode surfaces.
- `SELFDESTRUCT` reachability surfaces.
- Minimal proxy shells pointing at implementation bytecode.

These are evidence-backed `LEAD`/investigation findings. They are intentionally
not treated as submit-ready without live auth reads, selector dispatch
resolution, and fork/decompiler follow-up.

## Artifacts

For each scanned target:

```text
backend/outputs/scans/<scan_id>/<target>/tools/bytecode-intel/
  bytecode_intel.json
  disassembly.txt
```

The JSON artifact is also included in AI evidence packets and target
`coverage.json`.

## Run

```bash
python -m backend.main scan-one 0xTarget --chain ethereum --profile ultra-deep-v2
```

Per-scan API toggles can disable it with:

```json
{"bytecode_intel": false}
```

## Next Phase Candidate

Elite Phase 7 should attach a focused decompiler backend to each Phase 6 risk
signal and automatically generate selector-specific fork probes for
`delegatecall`, arbitrary executor, upgrade, and approval-drain bytecode paths.
