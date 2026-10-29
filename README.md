# shipment-workflow-benchmark

A FrontierSWE / Harbor evaluation task where an agent implements a crash-safe binary Write-Ahead Log (`wal.bin`), torn-tail crash recovery, mid-log corruption detection, atomic binary snapshot compaction (`snapshot.bin`), and a SHA-256 command-idempotent shipment workflow state machine in TypeScript / Node.js 22.

## Structure

- `instruction.md` — Full specification given to the agent
- `task.toml` — Harbor task configuration
- `environment/` — Dockerfile and starter TypeScript project (`/app/shipment-wal`)
- `tests/` — Isolated separate-container verifier (`test.sh` and `verify.mjs`)
- `solution/` — Reference oracle solution (`solve.sh`)
- `preflight/` — Container environment sanity check (`preflight_checks.sh`)
