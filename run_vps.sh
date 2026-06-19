#!/usr/bin/env bash
# Build the dashboard and serve EVERYTHING (UI + API) on a single fresh port.
# After this runs, the whole app is reachable at http://<host>:<PORT>/
#
# Port/host come from .env (PORT=8791, HOST=0.0.0.0 by default) or the
# environment. We deliberately avoid 8000 since that is already taken.
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8791}"
HOST="${HOST:-0.0.0.0}"

# 1) Python venv + deps
if [ ! -d venv ]; then
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install -q -r requirements.txt

# 2) Build the frontend so the backend can serve it (single port, same origin).
if [ -d frontend ]; then
  ( cd frontend && npm install --no-fund --no-audit && npm run build )
fi

# 3) Ensure .env exists
if [ ! -f .env ]; then
  cp .env.example .env
  echo "WARNING: created .env from template — edit it and add your API keys, then re-run."
fi

echo
echo "Serving BulkAuditAI on ${HOST}:${PORT}"
echo "  - same machine:  http://localhost:${PORT}/"
echo "  - from your PC:  open an SSH tunnel (see README) then http://localhost:${PORT}/"
echo

# 4) Launch (single process serves the built UI at / and the API at /api).
exec env HOST="$HOST" PORT="$PORT" python -m backend.main
