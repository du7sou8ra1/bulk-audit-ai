#!/usr/bin/env bash
# BulkAuditAI installer (Linux / VPS). Run from the project root.
# Safe to re-run. If a tool fails to install, the app still runs and marks that
# tool "missing" on the Tool Health page.
set -u

echo "==> apt packages"
sudo apt-get update
sudo apt-get install -y \
  curl git jq python3 python3-venv python3-pip nodejs npm build-essential

echo "==> Foundry (forge / cast / anvil)"
if ! command -v foundryup >/dev/null 2>&1; then
  curl -L https://foundry.paradigm.xyz | bash
  # shellcheck disable=SC1090
  source "$HOME/.bashrc" 2>/dev/null || true
  export PATH="$HOME/.foundry/bin:$PATH"
fi
foundryup || echo "WARN: foundryup failed; install Foundry manually (see README)."

echo "==> Python virtualenv"
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip

echo "==> Backend Python deps"
pip install -r requirements.txt || {
  echo "WARN: some pip installs failed; retrying core deps"
  pip install fastapi uvicorn sqlalchemy pydantic pydantic-settings python-dotenv \
    aiofiles httpx web3 eth-utils requests pandas
}

echo "==> Security tools (slither / mythril / semgrep / solc-select)"
pip install slither-analyzer mythril semgrep solc-select || \
  echo "WARN: one or more security tools failed to install; see README for manual steps."

# A common default solc; adjust per target contract.
solc-select install 0.8.19 2>/dev/null && solc-select use 0.8.19 2>/dev/null || true

echo "==> Frontend deps"
if [ -d frontend ]; then
  ( cd frontend && npm install ) || echo "WARN: npm install failed; run it manually in frontend/."
fi

echo
echo "Done. Next steps:"
echo "  1) cp .env.example .env   (then fill RPC_URL, ETHERSCAN_API_KEY, DEEPSEEK_API_KEY)"
echo "  2) source venv/bin/activate && python -m backend.main      # backend at :8000"
echo "  3) (separate shell) cd frontend && npm run dev             # UI at :5173"
echo
echo "Echidna is optional and installed separately (see README)."
