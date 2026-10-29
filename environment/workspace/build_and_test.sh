#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
tsc -p tsconfig.json
node tests/smoke.test.mjs

