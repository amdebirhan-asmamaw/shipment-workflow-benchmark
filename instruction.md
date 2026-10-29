# Crash-Safe Binary WAL & Idempotent Shipment State Machine Engine

Implement a crash-safe, event-sourced shipment workflow storage engine in TypeScript inside `/app/shipment-wal/`.

Your implementation must provide deterministic binary Write-Ahead Logging (`wal.bin`), torn-tail crash recovery, mid-log corruption detection, atomic binary snapshot compaction (`snapshot.bin`), and a SHA-256 command-idempotent 6-state shipment lifecycle state machine.

Build and run the public smoke suite at any time with:

```bash
./build_and_test.sh
```

Confine all source changes to `/app/shipment-wal/src/`. Do not change exported symbol names or method signatures in `src/types.ts`, `src/crc32.ts`, `src/wal.ts`, `src/snapshot.ts`, `src/engine.ts`, or `src/index.ts`. The runtime environment is offline and uses zero external npm runtime packages; rely solely on the Node.js 22 standard library (`node:fs`, `node:path`, `node:crypto`, `node:buffer`) and the pre-installed TypeScript compiler (`tsc`).

---

## 1. Canonical JSON & IEEE 802.3 CRC32 (`src/crc32.ts`)

### 1.1 Canonical JSON Serialization (`canonicalJson(value: unknown): string`)
All binary records and command idempotency digests depend on deterministic JSON encoding:
- Object keys at every nesting depth must be sorted in strictly ascending UTF-16 code-unit order (`Array.prototype.sort()`).
- Properties whose value is `undefined` must be omitted from objects.
- Arrays preserve element order.
- Output must have no insignificant whitespace (equivalent to `JSON.stringify` on recursively key-sorted objects).

### 1.2 CRC32 (`crc32(data: Uint8Array): number`)
- Compute the standard IEEE 802.3 32-bit cyclic redundancy check (polynomial `0xEDB88320` reflected, initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF`), returned as an unsigned 32-bit integer (`>>> 0`).
- Verification: `crc32(Buffer.from("123456789", "utf8")) === 0xCBF43926`.

### 1.3 Command Idempotency Fingerprint (`computeCommandHash(shipmentId: string, type: CommandType, payload: unknown): string`)
- Return the 64-character lowercase hexadecimal `SHA-256` digest of the UTF-8 bytes of:
  ```ts
  canonicalJson({ payload, shipmentId, type })
  ```
- Note that `commandId` and `timestamp` are excluded from the hash input so that retrying the same logical command for the same `shipmentId`, `type`, and `payload` (regardless of key ordering in `payload`) yields the identical digest.

---

## 2. Binary Write-Ahead Log (`src/wal.ts` — `wal.bin`)

### 2.1 File Layout
Every non-empty `wal.bin` starts with an **8-byte file header**:
- Bytes `0..6`: ASCII `"SHPWWAL"` (`0x53 0x48 0x50 0x57 0x57 0x41 0x4C`)
- Byte `7`: `uint8` version = `0x01`

If an existing WAL file has `size > 0` and its first 8 bytes do not exactly match `"SHPWWAL\x01"` (including files with `1 <= size < 8` whose bytes are not a prefix of `"SHPWWAL\x01"`, or a truncated file header with no valid header magic), wait:
- Specifically, if `0 < size < 8` and the bytes are an exact prefix of `"SHPWWAL\x01"`, treat it as a torn file header initialization: rewrite the 8-byte `"SHPWWAL\x01"` header (or truncate and write `"SHPWWAL\x01"`) with `0` frames. If the first `min(size, 8)` bytes do not match the corresponding prefix of `"SHPWWAL\x01"`, throw `WalCorruptionError` with `offset = 0` and `lsn = 0n`.

Immediately following byte `8` is a contiguous sequence of **frames**. Each frame consists of a **24-byte Big-Endian frame header** followed by `payload_len` bytes of UTF-8 canonical JSON payload:

| Byte Offset (within frame) | Type | Field | Description |
|---|---|---|---|
| `0..3` | `uint32 BE` | `magic` | Must be `0x53485057` (`"SHPW"`) |
| `4` | `uint8` | `version` | Must be `1` |
| `5` | `uint8` | `recordType` | `1` = `COMMAND_COMMIT`, `2` = `CHECKPOINT_MARKER` |
| `6..7` | `uint16 BE` | `flags` | Bit flags (`0` for standard records) |
| `8..15` | `BigUint64 BE` | `lsn` | Strictly sequential Log Sequence Number (`> 0n`) |
| `16..19` | `uint32 BE` | `payloadLen` | Byte length of UTF-8 payload (`0 < payloadLen <= 16_777_216`) |
| `20..23` | `uint32 BE` | `frameCrc32` | IEEE 802.3 CRC32 over header bytes `0..19` concatenated with the `payloadLen` payload bytes |
| `24..(24 + payloadLen - 1)` | `bytes` | `payload` | UTF-8 canonical JSON encoding of `WalPayload` |

### 2.2 LSN Continuity
- When opening a WAL with `baseLsn` (default `0n`, or `snapshot.lastLsn` when a snapshot exists), the first frame in `wal.bin` must have `lsn === baseLsn + 1n`, and every subsequent frame must have `lsn === previousFrame.lsn + 1n`.

### 2.3 Torn-Tail Recovery vs. Mid-Log Corruption Detection
When scanning `wal.bin` from offset `8` toward `EOF`:

1. **Torn-Tail Recovery (Truncate at Frame Offset & Succeed)**:
   A frame starting at byte offset `frameOffset` (`>= 8`) is classified as a **recoverable torn tail** if and only if **no valid frame magic (`0x53485057`) occurs anywhere after `frameOffset`** in the remaining bytes of the file, AND one of the following holds:
   - **Truncated Frame Header**: `EOF - frameOffset < 24`, and the remaining bytes at `frameOffset..EOF` are either a valid prefix of a frame header (i.e., the first `min(4, EOF - frameOffset)` bytes match the corresponding prefix of `0x53485057`) or trailing partial bytes at EOF. (Wait: if `EOF - frameOffset >= 4` and the first 4 bytes at `frameOffset` are NOT `0x53485057`, that is an invalid frame magic and must throw `WalCorruptionError`!).
   - **Truncated Frame Payload**: `EOF - frameOffset >= 24`, header fields (`magic === 0x53485057`, `version === 1`, `recordType in {1, 2}`, `lsn === expectedLsn`, `0 < payloadLen <= 16_777_216`) are valid, and `frameOffset + 24 + payloadLen > EOF`.
   - **Corrupted Final Frame at Exact EOF**: `EOF - frameOffset >= 24`, header fields (`magic === 0x53485057`, `version === 1`, `recordType in {1, 2}`, `lsn === expectedLsn`, `0 < payloadLen <= 16_777_216`) are valid, `frameOffset + 24 + payloadLen === EOF` (exact end of file — zero bytes follow this frame), and `frameCrc32` does not match the computed CRC32 (or the payload is invalid JSON).

   When a recoverable torn tail is detected at `frameOffset`:
   - Truncate `wal.bin` on disk to exact length `frameOffset` (and `fsync`).
   - Record `recoveredTornBytes = EOF - frameOffset` in `RecoveryStats`.
   - Stop scanning and return all valid frames prior to `frameOffset`.

2. **Mid-Log or Header Corruption (Throw `WalCorruptionError` Without Truncating)**:
   Throw `WalCorruptionError(message, frameOffset, expectedLsn)` and **do not modify or truncate `wal.bin`** if any of the following occurs:
   - `EOF - frameOffset >= 4` and `magic !== 0x53485057` (or `EOF - frameOffset < 4` and the bytes do not match the prefix of `0x53485057`).
   - `EOF - frameOffset >= 24` and (`version !== 1`, `recordType` is not `1` or `2`, or `payloadLen === 0` or `payloadLen > 16_777_216`).
   - `EOF - frameOffset >= 24` and `lsn !== expectedLsn` (LSN gap, duplicate, or regression).
   - `frameOffset + 24 + payloadLen < EOF` (more bytes exist after this frame) and either `frameCrc32` fails verification or the payload is not valid UTF-8 JSON.
   - `frameOffset + 24 + payloadLen > EOF` (truncated payload), **but** the 4-byte sequence `0x53485057` (`"SHPW"`) appears inside the remaining bytes after `frameOffset + 24` (indicating a corrupted `payloadLen` or torn middle record followed by subsequent frames).

---

## 3. Atomic Snapshot & Log Compaction (`src/snapshot.ts` — `snapshot.bin`)

### 3.1 Binary Snapshot Format (`snapshot.bin`)
| Byte Offset | Type | Field | Description |
|---|---|---|---|
| `0..7` | `bytes` | `magic` | 8-byte ASCII/version header `"SHPWSNP\x01"` (`0x53 0x48 0x50 0x57 0x53 0x4E 0x50 0x01`) |
| `8..15` | `BigUint64 BE` | `lastLsn` | Highest committed LSN captured in this snapshot |
| `16..19` | `uint32 BE` | `payloadLen` | Byte length of the canonical UTF-8 JSON snapshot body |
| `20..23` | `uint32 BE` | `snapCrc32` | IEEE 802.3 CRC32 over header bytes `0..19` concatenated with the `payloadLen` payload bytes |
| `24..(24 + payloadLen - 1)` | `bytes` | `payload` | Canonical UTF-8 JSON encoding of `SnapshotData` (`{ idempotencyIndex, lastLsn, shipments }`) |

If `snapshot.bin` exists on disk during recovery and is smaller than 24 bytes, has wrong magic/version, is truncated (`size !== 24 + payloadLen`), fails `snapCrc32` verification, or contains invalid JSON, throw `SnapshotCorruptionError(message, offset)`.

### 3.2 Crash-Safe Compaction Protocol
- `engine.compact()` compacts all committed state up to `currentLsn`.
- `engine.compactUpTo(targetLsn: bigint)` compacts state up to `targetLsn` (`0n <= targetLsn <= currentLsn`), retaining in `wal.bin` only frames with `lsn > targetLsn`.
- Compaction must be crash-safe:
  1. Write the new snapshot to `snapshot.bin.tmp`, `fsync`, and atomically `rename` to `snapshot.bin`.
  2. Write a replacement WAL to `wal.bin.tmp` (containing the 8-byte `"SHPWWAL\x01"` header followed by all valid frames with `lsn > targetLsn` with their original frame bytes/LSNs preserved), `fsync`, and atomically `rename` to `wal.bin`.
  3. On `ShipmentEngine.open(dataDir)`:
     - Remove any leftover `*.tmp` files (`snapshot.bin.tmp`, `wal.bin.tmp`) left behind by an interrupted compaction.
     - Load `snapshot.bin` if it exists (`baseLsn = snapshot.lastLsn`).
     - Note: if a crash occurred **after** `snapshot.bin` was atomically renamed to `targetLsn` but **before** `wal.bin.tmp` replaced `wal.bin`, `wal.bin` may still contain frames with `lsn <= snapshot.lastLsn`. During recovery, skip any valid prefix frames in `wal.bin` that have `lsn <= snapshot.lastLsn` (still verifying their CRC32 and sequential LSNs!), and ensure the first replayed frame after `snapshot.lastLsn` has `lsn === snapshot.lastLsn + 1n`!

---

## 4. Shipment State Machine & Command Idempotency (`src/engine.ts`)

### 4.1 Six-State Lifecycle
Each shipment is identified by a non-empty string `shipmentId` and progresses through these states:
- `CREATED`
- `BOOKED`
- `IN_TRANSIT`
- `HELD`
- `DELIVERED` (terminal)
- `CANCELLED` (terminal)

### 4.2 Commands, Validation Rules & State Transitions

Every command passed to `engine.executeCommand(cmd: ShipmentCommand)` has the shape:
```ts
interface ShipmentCommand {
  commandId: string;
  shipmentId: string;
  type: CommandType;
  timestamp: number;
  payload: Record<string, unknown>;
}
```

#### General Validation (`ValidationError`)
Before checking state transitions (but **after** checking `commandId` idempotency):
- `commandId` and `shipmentId` must be non-empty strings (`trim().length > 0`).
- `timestamp` must be a finite integer (`Number.isSafeInteger(cmd.timestamp) && cmd.timestamp >= 0`).
- If `shipment` already exists, `cmd.timestamp` must be `>= shipment.updatedAtTs`; otherwise throw `ValidationError`.

#### Per-Command Rules
1. **`CREATE`**:
   - **Allowed from**: Shipment does not exist yet (if shipment already exists, throw `InvalidTransitionError`).
   - **Payload**: `{ origin: string, destination: string, weightKg: number, declaredValueCents: number }`
   - **Validation**:
     - `origin` and `destination` must be non-empty strings (`trim().length > 0`) and `origin !== destination`.
     - `weightKg` must be a finite number `> 0`.
     - `declaredValueCents` must be a safe integer `>= 0`.
   - **Effect**: Creates shipment in state `CREATED`, setting `createdAtTs = cmd.timestamp`, `updatedAtTs = cmd.timestamp`, `version = 1`, `lastCommandId = cmd.commandId`, `lastLsn = assignedLsn`, and storing `origin`, `destination`, `weightKg`, `declaredValueCents`.

2. **`BOOK`**:
   - **Allowed from**: `CREATED` (any other state or non-existent shipment throws `InvalidTransitionError`).
   - **Payload**: `{ carrierId: string, vesselOrFlight: string, scheduledDepartureTs: number }`
   - **Validation**:
     - `carrierId` and `vesselOrFlight` must be non-empty strings.
     - `scheduledDepartureTs` must be a safe integer `>= shipment.createdAtTs`.
   - **Effect**: Transitions to `BOOKED`, sets `carrierId`, `vesselOrFlight`, `scheduledDepartureTs`, updates `updatedAtTs = cmd.timestamp`, increments `version`.

3. **`DISPATCH`**:
   - **Allowed from**: `BOOKED`
   - **Payload**: `{ departedAtTs: number, originPort: string }`
   - **Validation**:
     - `originPort` must be a non-empty string.
     - `departedAtTs` must be a safe integer `>= shipment.scheduledDepartureTs!` and `<= cmd.timestamp`.
   - **Effect**: Transitions to `IN_TRANSIT`, sets `departedAtTs`, `originPort`, updates `updatedAtTs = cmd.timestamp`, increments `version`.

4. **`HOLD`**:
   - **Allowed from**: `BOOKED` or `IN_TRANSIT`
   - **Payload**: `{ reasonCode: string, heldAtTs: number }`
   - **Validation**:
     - `reasonCode` must be a non-empty string.
     - `heldAtTs` must be a safe integer `>= shipment.updatedAtTs` and `<= cmd.timestamp`.
   - **Effect**: Saves current state (`"BOOKED"` or `"IN_TRANSIT"`) into `shipment.heldFromState`, sets `holdReason = reasonCode`, `heldAtTs`, transitions to `HELD`, updates `updatedAtTs = cmd.timestamp`, increments `version`.

5. **`RESUME`**:
   - **Allowed from**: `HELD`
   - **Payload**: `{ resumedAtTs: number, clearanceRef: string }`
   - **Validation**:
     - `clearanceRef` must be a non-empty string.
     - `resumedAtTs` must be a safe integer `>= shipment.heldAtTs!` and `<= cmd.timestamp`.
   - **Effect**: Restores `shipment.state` back to `shipment.heldFromState!` (`"BOOKED"` or `"IN_TRANSIT"`), clears `heldFromState = null` and `holdReason = null`, sets `resumedAtTs` and `clearanceRef`, updates `updatedAtTs = cmd.timestamp`, increments `version`.

6. **`DELIVER`**:
   - **Allowed from**: `IN_TRANSIT`
   - **Payload**: `{ deliveredAtTs: number, receiverSignature: string }`
   - **Validation**:
     - `receiverSignature` must be a non-empty string.
     - `deliveredAtTs` must be a safe integer `>= shipment.departedAtTs!` and `<= cmd.timestamp`.
   - **Effect**: Transitions to `DELIVERED`, sets `deliveredAtTs`, `receiverSignature`, updates `updatedAtTs = cmd.timestamp`, increments `version`.

7. **`CANCEL`**:
   - **Allowed from**: `CREATED`, `BOOKED`, or `HELD` (cannot cancel from `IN_TRANSIT`, `DELIVERED`, or `CANCELLED`).
   - **Payload**: `{ cancelledAtTs: number, reason: string }`
   - **Validation**:
     - `reason` must be a non-empty string.
     - `cancelledAtTs` must be a safe integer `>= shipment.updatedAtTs` and `<= cmd.timestamp`.
   - **Effect**: Transitions to `CANCELLED`, clears `heldFromState = null`, sets `cancelledAtTs` and `cancelReason = reason`, updates `updatedAtTs = cmd.timestamp`, increments `version`.

### 4.3 SHA-256 Command Idempotency & Failure Atomicity
When `executeCommand(cmd)` is called:
1. Validate that `cmd.commandId`, `cmd.shipmentId`, and `cmd.type` are non-empty strings.
2. Compute `cmdHash = computeCommandHash(cmd.shipmentId, cmd.type, cmd.payload)`.
3. Lookup `cmd.commandId` in the engine's persisted `idempotencyIndex`:
   - If found and `entry.commandHash === cmdHash`:
     - Do **not** append any frame to `wal.bin` and do **not** advance `currentLsn`.
     - Return `{ lsn: entry.lsn, shipment: structuredClone(entry.resultSnapshot), deduplicated: true }`.
   - If found and `entry.commandHash !== cmdHash`:
     - Do **not** append any frame to `wal.bin` and do **not** advance `currentLsn`.
     - Throw `IdempotencyConflictError`.
4. If `cmd.commandId` is not in `idempotencyIndex`:
   - Validate the command and state transition. If `ValidationError` or `InvalidTransitionError` is thrown, **no frame may be written to `wal.bin`**, `currentLsn` must not change, and `idempotencyIndex` must not record the failed command.
   - Otherwise, assign `nextLsn = currentLsn + 1n`, apply the state transition to produce the updated `ShipmentRecord`, append and `fsync` a `COMMAND_COMMIT` (`recordType = 1`) WAL frame containing `{ command: cmd, commandHash: cmdHash, lsn: nextLsn.toString(), shipment: updatedShipment }`, record `{ commandId: cmd.commandId, commandHash: cmdHash, lsn: nextLsn, resultSnapshot: updatedShipment }` in `idempotencyIndex`, and return `{ lsn: nextLsn, shipment: structuredClone(updatedShipment), deduplicated: false }`.

