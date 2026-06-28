# BulkAuditAI

Bulk-triage EVM smart contracts for **critical vulnerability candidates**, using
static analysis, read-only on-chain checks, bytecode intelligence, custom
2020-2026 exploit detectors, invariant/fuzz scaffolding, optional fork
simulations, adversarial refutation, and a strict **DeepSeek/OpenAI-compatible**
AI review layer.

> **Defensive security research & bug-bounty triage only.**
> It never sends transactions, never needs a private key, never exploits live
> contracts, and never auto-submits reports. Every dynamic check is `eth_call`,
> a local fork test, or local simulation.

`candidate ≠ confirmed bug` · `governance power ≠ bug (unless unauthorized/mismatched)` · `AI opinion ≠ proof`

---

## What it does

1. Paste many contract addresses → pick a chain + scan profile → start a bulk scan.
2. Watch progress live (WebSocket), per-target and per-tool.
3. For each contract: fetch verified source/ABI/bytecode, resolve proxy →
   implementation → admin/owner, run Slither/Mythril/Semgrep, bytecode intel,
   bytecode probes, custom detectors, invariant reasoning, optional fuzz/fork
   scaffolds, read-only value-context probes, adversarial refutation, scoring,
   and DeepSeek/OpenAI-compatible AI triage.
4. Review findings with **two scores** (impact 0–10 and confidence 0–10) and a
   classification: `CONFIRMED_CRITICAL`, `LIKELY_CRITICAL_NEEDS_POC`,
   `NEEDS_MORE_INVESTIGATION`, `LOW_OR_INFO`, `FALSE_POSITIVE`.
5. Export JSON / CSV / Markdown report draft / zipped evidence.

---

## Architecture

```
FastAPI backend (asyncio scan worker, SQLite)  ──WebSocket──►  React + Vite + Tailwind UI
        │
        ├─ source_fetcher  (Etherscan v2 + Sourcify fallback)
        ├─ proxy_resolver  (EIP-1967 slots + admin/owner reads)
        ├─ onchain         (read-only RPC, eth_call, storage/balance/code reads)
        ├─ bytecode_intel / bytecode_probes
        ├─ detectors/      (deep, ultra-deep, ultra-deep-v2 exploit classes)
        ├─ runners/        (slither, mythril, semgrep, foundry/fuzz scaffolds)
        ├─ invariant_reasoner / refuter / ai_reviewer
        ├─ scoring         (impact/confidence + precision guardrails)
        └─ evidence / exporter / report_writer / scanner
```

Per-scan **isolated workspace** (never overwrites old scans):

```
backend/outputs/scans/<scan_id>/<address>/
  source/  tools/{slither,mythril,semgrep,foundry}/  evidence/  ai/  reports/
```

---

## Tool and detector stack

### External analyzers

| Tool | Purpose | Notes |
|------|---------|-------|
| Slither | Static Solidity analysis | Runs from a neutral cwd to avoid Foundry project confusion. |
| Mythril | Symbolic execution / bytecode fallback | Source compile can fail; bytecode fallback is used when possible. |
| Semgrep | Solidity pattern rules | Used as corroboration, not proof. |
| Foundry | Read-only fork PoCs and simulations | Never broadcasts; private keys and broadcast commands are blocked. |
| Fuzzing / invariants | Starter suites and detector-focused invariant harnesses | Generates harnesses/scaffolds; a scaffold is not counted as a passed PoC. |
| DeepSeek/OpenAI-compatible model | Triage, invariant hypotheses, adversarial refutation | Uses strict prompts and post-processing guardrails. |

### Built-in analysis layers

- Source and ABI fetch: Etherscan v2 first, Sourcify fallback when enabled.
- Proxy intelligence: EIP-1967 implementation/admin slots, owner/admin classifier, proxy/implementation merge.
- Bytecode intelligence: selector clusters, opcode risk signals, closed-source surface hints.
- Bytecode probes: selector-specific fork probe plans for high-risk bytecode surfaces.
- 2020-2026 exploit detectors: bridge replay/domain binding, settlement-boundary mismatch, zero-value transfer reward stacking, ERC777 hook accounting, read-only reserve reentrancy, unsafe mint math, CLMM tick boundary rounding, lending donation exchange-rate manipulation, verifier spoofing, upgrade/admin blast radius, and more.
- Weird-hunt detector pack: actual-received accounting, Merkle leaf binding, bitmap claim collision, bridge replay keys, address aliasing, oracle freshness/sequencer, TWAP cardinality, forced ETH accounting, CREATE2/metamorphic trust, try/catch finalization, reward-debt order, zero-supply accumulators, position split/merge, governance snapshot bypass, pause bypass, multicall state cache, WAD/RAY unit mismatch, duplicate batch items, and semantic taint value-flow leads.
- Semantic index: shared Solidity facts for params, modifiers, guards, reads/writes, calls, decoded fields, events, mappings, external calls, and value sinks.
- Taint/dataflow core: caller/calldata/proof/oracle sources into value-transfer, delegatecall, upgrade, replay-marker, and accounting-write sinks, including simple external -> internal helper paths.
- Invariant reasoner: LLM-assisted cross-function hypotheses over value-moving entrypoints.
- Adversarial refuter: independent review pass that tries to disprove each candidate before final scoring.
- Value-context probe: read-only balance/asset/totalSupply/totalAssets checks plus ABI/source value-flow hints. Unknown RPC data never suppresses a bug by itself.
- Precision guardrails: caller-bound `transferFrom(msg.sender, ...)` false-positive gate, critical-value gate, and pattern-prior context.

### Precision guardrails added in the latest upgrade

- Critical claims must answer: what value moves, where it moves, and why the destination is attacker-controlled.
- AI/refuter output must cite attacker-control bindings instead of inventing them.
- Caller-bound transfer sources such as `from = msg.sender` are deterministically refuted for approval-drain claims.
- `value_context.state = unknown` is never treated as proof that a target is safe.
- `value_context.state = no_value` with `signal = inert_unreferenced` can cap severity for obviously inert contracts.
- Prior concrete refutations can be attached as context in later scans without automatically suppressing new findings.
- PoC generation now prioritizes higher-impact, corroborated, rare, cross-function, and economic-leverage candidates first.

---

## Install

### Linux / VPS (recommended)

```bash
git clone <your-repo> bulk-audit-ai && cd bulk-audit-ai
bash install_tools.sh           # apt deps, Foundry, venv, python deps, security tools, npm install
cp .env.example .env            # then fill in your keys (see below)
```

If a security tool fails to install, the app still runs — it just marks that tool
**missing** on the **Tool Health** page and records a *skipped* ToolRun.

### Windows (development)

Security tools (Slither/Mythril) are easiest on Linux/WSL, but the app runs on
Windows for development and triage of the source/on-chain/AI layers:

```powershell
python -m venv venv ; .\venv\Scripts\Activate.ps1
pip install -r requirements.txt        # or just the core deps if security tools fail
copy .env.example .env
```

### Manual tool install (if the script fails)

Install the analyzers with **pipx** (each in its own venv — this avoids the
`web3`/`mythril` dependency conflict; never `pip install` them into the app venv):

| Tool | Install |
|------|---------|
| pipx | `sudo apt-get install -y pipx` (or `python3 -m pip install --user pipx`) |
| Slither | `pipx install slither-analyzer` |
| Semgrep | `pipx install semgrep` |
| solc-select | `pipx install solc-select` then `solc-select install 0.8.19 && solc-select use 0.8.19` |
| Mythril | `pipx install mythril` (finicky — OK to skip; app marks it missing) |
| Foundry | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |

After pipx installs, make sure `~/.local/bin` is on your `PATH` (`pipx ensurepath`).
| Echidna (optional) | see https://github.com/crytic/echidna (binary release) |

---

## Configure (`.env`)

```bash
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/...   # READ-ONLY RPC
ETHERSCAN_API_KEY=...
DEEPSEEK_API_KEY=...
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

ENABLE_SLITHER=true
ENABLE_MYTHRIL=true
ENABLE_SEMGREP=true
ENABLE_FOUNDRY=false
ENABLE_FUZZING=false
ENABLE_DEEPSEEK=true

ENABLE_BYTECODE_INTEL=true
ENABLE_BYTECODE_PROBES=true
ENABLE_INVARIANT_REASONER=true
ENABLE_REFUTATION=true
ENABLE_SOURCIFY=true
ENABLE_VALUE_CONTEXT=true
ENABLE_SANITY_LIVENESS=true
ENABLE_REFUTER_PRECISION_RULES=true
ENABLE_BINDING_HARD_GATE=true
ENABLE_CRITICAL_VALUE_GATE=true
ENABLE_PATTERN_PRIORS=true
REFUTATION_MODE=hard              # hard|soft
MAX_HYPOTHESES_PER_TARGET=8
MAX_POCS_PER_TARGET=3
ENABLE_FLASHLOAN_SIM=true
MAX_SIMS_PER_TARGET=2
```

Secrets are read from `.env` only. They are **never stored in SQLite** and are
shown **masked** in the UI (`/api/settings`). The DeepSeek key is OpenAI-compatible,
so you can point `DEEPSEEK_BASE_URL` at any compatible endpoint (e.g. OpenRouter).

---

## Run

Ports are deliberately **off the common defaults** (8000 was already taken):
the backend/API serves on **8791**, the dev UI on **5891**.

### Local development (two processes)

```bash
# Backend + API  → http://localhost:8791   (API docs at /docs)
source venv/bin/activate
python -m backend.main

# Dev UI         → http://localhost:5891   (proxies /api and /ws to :8791)
cd frontend && npm install && npm run dev
```

### Single-port (one process serves UI + API — best for a VPS)

```bash
cd frontend && npm install && npm run build   # produces frontend/dist
cd .. && python -m backend.main                # serves the UI at / on :8791
```

### CLI

```bash
python -m backend.main scan --addresses addresses.txt --profile ultra-deep-v2
python -m backend.main scan-one 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
python -m backend.main export --scan-id 1 --format zip
```

---

## Deploy on a VPS + reach it as a website on your PC

The whole app runs as **one process on one fresh port (8791)** — no nginx
required. Change the port any time via `PORT=...` in `.env` or the environment.

### 1. On the VPS — install + run

```bash
git clone <your-repo> bulk-audit-ai && cd bulk-audit-ai
bash install_tools.sh         # apt deps, Foundry, venv, python + security tools, npm install
cp .env.example .env          # then add RPC_URL / ETHERSCAN_API_KEY / DEEPSEEK_API_KEY
bash run_vps.sh               # builds the UI and serves UI+API on :8791
```

`run_vps.sh` honours `PORT` and `HOST`:

```bash
PORT=9412 HOST=127.0.0.1 bash run_vps.sh   # pick any free port; bind localhost for tunnel use
```

Keep it running across reboots/logout with systemd (recommended):

```ini
# /etc/systemd/system/bulkauditai.service
[Unit]
Description=BulkAuditAI
After=network.target

[Service]
WorkingDirectory=/home/youruser/bulk-audit-ai
Environment=HOST=127.0.0.1
Environment=PORT=8791
ExecStart=/home/youruser/bulk-audit-ai/venv/bin/python -m backend.main
Restart=on-failure
User=youruser

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now bulkauditai
# (build the UI once first: cd frontend && npm install && npm run build)
```

### 2. From your PC — open the dashboard

**Recommended: SSH tunnel (secure — the app has NO login).** Bind the VPS
service to `127.0.0.1` (as above) so it is *not* exposed publicly, then forward
the port from your PC:

```bash
# On your PC (Windows PowerShell, macOS, or Linux all have ssh):
ssh -N -L 8791:localhost:8791 youruser@YOUR_VPS_IP
```

Leave that running and open **http://localhost:8791/** in your browser — you now
have the full dashboard, served from the VPS, on your PC.

**Alternative: expose the port directly** (only if you understand the risk —
there is no authentication, so anyone who finds the port can use it and see your
scan data). Set `HOST=0.0.0.0`, open the port in the VPS firewall, and browse
`http://YOUR_VPS_IP:8791/`. If you do this, put it behind a reverse proxy with
HTTP basic-auth or an allowlist.

> Secrets (`RPC_URL`, `ETHERSCAN_API_KEY`, `DEEPSEEK_API_KEY`) live only in the
> VPS `.env`; the dashboard shows them masked and never stores them in SQLite.

---

## Scan profiles

| Profile | What runs | Best use |
|---------|-----------|----------|
| `deep` | Core detector set and standard tooling | Faster triage, lower noise. |
| `ultra-deep` | `deep` plus additional exploit-family detectors | Stronger audit pass when source is verified. |
| `ultra-deep-v2` | `deep` + `ultra-deep` + corpus, bytecode, bridge, ZK, oracle, accounting, hook, settlement, and 2026 exploit-class detectors | Strongest current model. Use this for serious exploited-contract regression tests and bounty-style review. |

`ultra-deep-v2` is currently the most powerful profile. It includes the older
`deep` and `ultra-deep` detector families plus the newer bytecode/corpus/2026
classes and precision layers.

### Main detector families

- Access control, owner/admin/timelock roles, governance blast radius.
- Proxy upgrade and uninitialized/reinitializable proxy surfaces.
- Arbitrary calls, delegatecall, multisig delegatecall payloads, self-call auth bypass.
- Permit/signature replay, ECDSA/ecrecover zero-address, EIP-1271 spoofing.
- Bridge accounting, retry/domain binding, keeper mutation, zero-root acceptance, cross-chain source auth.
- ZK/settlement-boundary mismatch, verifier address spoofing, single-verifier bridge config.
- Token/accounting logic: zero-value transfer reward checkpoint, zero-value transferFrom bypass, component share accounting, vault donation inflation, lending exchange-rate donation, unsafe mint math.
- Hooks and callback risks: ERC777 balance bypass, hook callback auth, pair burn/sync issues, receiver-hook credit, deposit callback CEI.
- Oracle and market math: thin-liquidity spot oracle, read-only reserve reentrancy, CLMM tick boundary rounding, invariant precision loss, decimal unit mismatch.
- 2026 classes: settlement count/boundary mismatch, flawed zero-value transfer reward stacking, callback payer/proof binding, memory-vs-storage persistence, signer allowlist, fee-on-transfer swap bounds, asymmetric SafeMath, and more.
- Weird-hunt classes: actual-received accounting, weak Merkle binding, bitmap claim aliasing, bridge replay keys, L1/L2 address alias mismatch, Chainlink freshness/sequencer checks, TWAP cardinality/period mistakes, forced ETH accounting, CREATE2/metamorphic trust, try/catch finalization, reward-debt update order, zero-supply reward accumulators, position split/merge duplication, governance snapshot bypass, pause bypass, multicall `msg.value` reuse, WAD/RAY/unit mismatch, duplicate batch items, and cross-function calldata-to-value-sink taint flow.

### Per-scan toggles

The New Scan page can enable/disable: Slither, Mythril, Semgrep, Foundry, fuzzing,
bytecode intel, bytecode probes, DeepSeek review, invariant reasoner, refutation,
flashloan simulations, value-context, sanity liveness, binding hard gate, and
pattern priors. Server defaults are shown on the Settings page.

### Auto-PoC and fuzzing

When `ENABLE_FOUNDRY=true`, `forge` is installed, and an RPC is configured, strong
eligible candidates get generated read-only fork PoCs. `MAX_POCS_PER_TARGET`
controls the cap. The scanner prioritizes higher-impact, corroborated,
economic, rare, cross-function, and PoC-ready candidates before spending PoC
budget.

Fuzzing currently generates readiness reports, starter suites, and
detector-focused invariant harnesses. These are validation scaffolds; they are
not counted as passed exploits unless a real assertion/test succeeds.

## Scoring & classification

Detectors emit base `impact` + `confidence` (0–10). Scoring then adjusts:
`+2` static-tool agreement, `+1` on-chain open-role confirmation,
`−3` governance-owner-only power, `−3` documented centralization, and caps
confidence when there's no demonstrated unauthorized path / no PoC.

```
impact ≥ 9 and confidence ≥ 8  → CONFIRMED_CRITICAL
impact ≥ 9 and confidence 5–7  → LIKELY_CRITICAL_NEEDS_POC
impact ≥ 7 and confidence 3–5  → NEEDS_MORE_INVESTIGATION
otherwise                      → LOW_OR_INFO
```

**AI guardrail:** DeepSeek cannot return `CONFIRMED_CRITICAL` unless the evidence
already shows a reproducible unauthorized path (open on-chain role, unguarded
selector, or a passing fork/eth_call PoC) - otherwise it is auto-downgraded.

**Critical-value guard:** critical theft claims must show the value movement
triad: asset/value moved, destination, and attacker control of that destination.
If that triad is missing, the result is capped to `NEEDS_MORE_INVESTIGATION`.

**Rare-lead handling:** `lead_only` findings and high-impact unrefuted structural
leads are kept visible at investigation level instead of being buried as info.
`REFUTATION_MODE=soft` can also keep rare/economic/cross-function leads visible
when you prefer discovery over aggressive suppression.

---

## Safety constraints (enforced)

- Read-only RPC only: `eth_call`, `eth_call` with explicit `from`,
  `eth_getCode`, `eth_getStorageAt`, `eth_getBalance`, `eth_getLogs`.
  No `eth_sendTransaction` /
  `eth_sendRawTransaction` / signing anywhere in the code.
- No private keys, no wallet connection.
- Foundry runs **fork tests only**; the runner refuses any file containing
  `--broadcast` / `vm.broadcast` / `cast send` / private-key tokens.
- No auto-submission to bounty platforms. Report drafts are marked
  *"Not submit-ready"* until a PoC/fork confirmation exists.

---

## Tests

```bash
pip install pytest
pytest            # full backend test suite
cd frontend && npm run build
```

Current validation covers detector fixtures, proxy/source handling, scoring,
AI/refuter precision guardrails, value-context behavior, fuzzing harness
generation, bytecode intelligence, and scan manager behavior.

---

## Project layout

```
backend/   FastAPI app, core/, detectors/, runners/, api/, prompts/, templates/, semgrep_rules/
frontend/  React + Vite + TypeScript + Tailwind dashboard
tests/     pytest suite + Solidity fixtures
install_tools.sh   .env.example   requirements.txt   docker-compose.yml
```

## Roadmap / next phase

Elite Phase 8 is implemented: `backend/core/semantic_index.py` builds shared
Solidity facts, and `backend/core/taint.py` follows caller/calldata/proof/oracle
sources into value-transfer, delegatecall, upgrade, replay-marker, and accounting
write sinks. Each scan attaches `ctx.semantic`, `ctx.taint`, and a taint summary.

Elite Phase 9 is implemented: `backend/detectors/weird_hunt.py` adds the
weird-bug detector pack to `ultra-deep-v2`, including actual-received
accounting, Merkle/bitmap/bridge replay binding, oracle/TWAP/forced-ETH,
CREATE2/metamorphic trust, try/catch finalization, reward-debt order,
zero-supply accumulator, position lifecycle, governance snapshot, pause bypass,
multicall state cache, WAD/RAY unit mismatch, duplicate batch items, and
semantic taint value-flow leads.

Recommended next improvements:

1. **Elite Phase 10 - detector evidence hardening**: upgrade `privacy_pool`,
   `delegatecall`, `zk_verifier`, and access-control custom-guard precision to
   consume semantic/taint facts directly.
2. Add Semgrep corroboration rules and Foundry templates for each weird-hunt
   family.
3. Add protocol graph and storage-layout hints for cross-contract bugs.
4. Add a regression benchmark set of exploited contracts with expected detector
   hits, so each deploy can prove it still catches Aztec/Royalties/Euler/Nomad
   style bugs.
