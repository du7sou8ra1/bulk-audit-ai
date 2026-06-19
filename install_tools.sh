#!/usr/bin/env bash
# BulkAuditAI installer (Linux / VPS). Run from the project root.
# Safe to re-run. If a tool fails to install, the app still runs and marks that
# tool "missing" on the Tool Health page.
set -u

echo "==> apt packages"
sudo apt-get update
sudo apt-get install -y \
  curl git jq python3 python3-venv python3-pip python3-dev nodejs npm build-essential
# pipx (isolated installs for the CLI security tools). Best-effort across distros.
sudo apt-get install -y pipx 2>/dev/null || python3 -m pip install --user -q pipx || true

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

echo "==> Backend Python deps (core only — no security tools in this venv)"
pip install -r requirements.txt || {
  echo "WARN: some pip installs failed; retrying core deps"
  pip install fastapi "uvicorn[standard]" sqlalchemy pydantic pydantic-settings \
    python-dotenv aiofiles httpx web3 eth-utils eth-abi requests pandas
}

echo "==> Security tools via pipx (isolated — avoids the web3/mythril conflict)"
# pipx installs each CLI in its own venv, so their (conflicting) deps never touch
# the app venv. The app calls these as subprocesses on PATH.
export PATH="$HOME/.local/bin:$PATH"
python3 -m pipx ensurepath >/dev/null 2>&1 || pipx ensurepath >/dev/null 2>&1 || true
PIPX="python3 -m pipx"; command -v pipx >/dev/null 2>&1 && PIPX="pipx"
for tool in slither-analyzer semgrep solc-select mythril; do
  echo "  - pipx install $tool"
  $PIPX install "$tool" \
    || echo "    WARN: $tool failed to install (mythril is finicky; the app still runs and marks it missing on Tool Health)."
done

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
