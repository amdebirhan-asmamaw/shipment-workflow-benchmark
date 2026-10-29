#!/usr/bin/env bash
set -euo pipefail

echo "[preflight] Checking runtime environment..."
node --version
tsc --version

if [ ! -d "/app/shipment-wal" ]; then
  echo "[preflight] ERROR: /app/shipment-wal does not exist" >&2
  exit 1
fi

if ! id -u agent >/dev/null 2>&1; then
  echo "[preflight] ERROR: non-root user 'agent' is missing" >&2
  exit 1
fi

echo "[preflight] All environment checks passed."

