#!/usr/bin/env bash
set -uo pipefail

mkdir -p /logs/verifier

if [ ! -d "/app/shipment-wal/src" ]; then
  echo "0.000" > /logs/verifier/reward.txt
  exit 0
fi

# Prevent dist/ or tsconfig.json tampering: wipe dist/ and compile from src/ using a verifier-controlled tsconfig
rm -rf /app/shipment-wal/dist /tmp/verifier.tsconfig.json

cat <<'EOF' > /tmp/verifier.tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "rootDir": "/app/shipment-wal/src",
    "outDir": "/app/shipment-wal/dist",
    "strict": true,
    "declaration": true,
    "sourceMap": false,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "typeRoots": [
      "/usr/local/lib/node_modules/@types"
    ],
    "types": [
      "node"
    ]
  },
  "include": [
    "/app/shipment-wal/src/**/*.ts"
  ]
}
EOF

if ! tsc -p /tmp/verifier.tsconfig.json >/tmp/tsc_verify.log 2>&1; then
  cat /tmp/tsc_verify.log >&2
  echo "0.000" > /logs/verifier/reward.txt
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if ! node "${SCRIPT_DIR}/verify.mjs"; then
  if [ ! -f /logs/verifier/reward.txt ]; then
    echo "0.000" > /logs/verifier/reward.txt
  fi
fi
