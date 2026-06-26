# Elite Phase 5 Exploit Benchmark

Phase 5 adds a regression gate for known exploited contracts. The goal is to
catch detector or fuzz-harness regressions before they reach `ultra-deep-v2`.

## Commands

List the benchmark pack:

```bash
python -m backend.main benchmark-exploits --list-cases
```

Validate existing scans:

```bash
python -m backend.main benchmark-exploits --scan-id 78 --scan-id 79
```

Run the benchmark pack and validate the new scans:

```bash
ENABLE_FUZZING=true ENABLE_DEEPSEEK=false ENABLE_REFUTATION=false \
ENABLE_INVARIANT_REASONER=false ENABLE_MYTHRIL=false ENABLE_SLITHER=false \
ENABLE_SEMGREP=false ENABLE_FOUNDRY=false FUZZ_TIMEOUT=90 MAX_PARALLEL_TARGETS=1 \
python -m backend.main benchmark-exploits --run --out backend/outputs/elite5-benchmark.json
```

## Gates

Each case declares:

- the chain and deployed contract address
- expected detector family or families
- minimum critical finding count
- whether `fuzz-invariants` must run successfully
- minimum generated stateful scenario count
- minimum asset/accounting probe counts when the contract exposes useful getters

The command exits non-zero if any expected exploit signal disappears.
