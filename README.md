# BulkAuditAI

Bulk-triage Ethereum smart contracts for **critical vulnerability candidates**, using
static analysis, read-only on-chain checks, custom detectors, optional fork
simulations, and a strict **DeepSeek** AI review layer.

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
   implementation → admin/owner, run Slither/Mythril/Semgrep + custom detectors,
   probe roles on-chain, score, and ask DeepSeek to classify.
4. Review findings with **two scores** (impact 0–10 and confidence 0–10) and a
   classification: `CONFIRMED_CRITICAL`, `LIKELY_CRITICAL_NEEDS_POC`,
   `NEEDS_MORE_INVESTIGATION`, `LOW_OR_INFO`, `FALSE_POSITIVE`.
5. Export JSON / CSV / Markdown report draft / zipped evidence.

---

## Architecture

```
FastAPI backend (asyncio scan worker, SQLite)  ──WebSocket──►  React + Vite + Tailwind UI
        │
        ├─ source_fetcher  (Etherscan v2)        ├─ detectors/  (framework + 5 MVP detectors + stubs)
        ├─ proxy_resolver  (EIP-1967 slots)      ├─ runners/    (slither, mythril, semgrep, foundry)
        ├─ onchain         (read-only RPC)        ├─ scoring     (impact/confidence → classification)
        ├─ evidence        (workspace + packets)  ├─ ai_reviewer (DeepSeek, strict)
        └─ exporter / report_writer               └─ scanner     (pipeline orchestrator)
```

Per-scan **isolated workspace** (never overwrites old scans):

```
backend/outputs/scans/<scan_id>/<address>/
  source/  tools/{slither,mythril,semgrep,foundry}/  evidence/  ai/  reports/
```

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
ENABLE_DEEPSEEK=true
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
python -m backend.main scan --addresses addresses.txt --profile standard
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

| Profile | Detectors |
|---------|-----------|
| `quick` | proxy upgrade, arbitrary call |
| `standard` | the 5 MVP detectors |
| `deep` | all detectors (incl. stubs) |
| `governance-focused` | governance blast radius, timelock roles, proxy upgrade |
| `zk-focused` | MVP + ZK verifier (stub) |
| `privacy-pool-focused` | MVP + privacy pool (stub) |
| `bridge-focused` | MVP + bridge accounting |

### Detector status

**Fully implemented:** `proxy_upgrade`, `timelock_roles`, `arbitrary_call`,
`permit_misuse`, `governance_blast_radius`, `bridge_accounting` (v0.2).

**Stubs (framework only, return no findings — TODOs inside):** `delegatecall`,
`access_control`, `token_logic`, `zk_verifier`, `privacy_pool`.

### Auto-PoC (v0.2)

When `ENABLE_FOUNDRY=true`, `forge` is installed, and an RPC is configured,
strong eligible candidates get an auto-generated **read-only fork PoC** that asks
whether an unprivileged caller can invoke the privileged selector. The PoC runs
only on a local fork (never broadcasts; ffi/keys disabled), and `poc_passed` is
set **only when forge confirms a test actually executed and succeeded** — a
passing PoC is what lets a finding reach `CONFIRMED_CRITICAL`.

---

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
selector, or a passing fork/eth_call PoC) — otherwise it is auto-downgraded.

---

## Safety constraints (enforced)

- Read-only RPC only: `eth_call`, `eth_getCode`, `eth_getStorageAt`,
  `eth_getBalance`, `eth_getLogs`. No `eth_sendTransaction` /
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
pytest            # proxy slot math, minimal-proxy detection, scoring thresholds, detectors on fixtures
```

Fixtures: `tests/fixtures/VulnerableUpgradeable.sol` (must produce findings) and
`SafeVault.sol` (must NOT produce a fake critical).

---

## Project layout

```
backend/   FastAPI app, core/, detectors/, runners/, api/, prompts/, templates/, semgrep_rules/
frontend/  React + Vite + TypeScript + Tailwind dashboard
tests/     pytest suite + Solidity fixtures
install_tools.sh   .env.example   requirements.txt   docker-compose.yml
```

## Roadmap (v0.2)

Foundry-generated fork PoCs run automatically for strong candidates; flesh out the
stub detectors (delegatecall data-flow, bridge accounting, ZK verifier, privacy
pool); multi-chain; Echidna property tests.
