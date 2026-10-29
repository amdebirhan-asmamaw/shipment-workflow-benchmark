#!/usr/bin/env bash
set -euo pipefail

cd /app/shipment-wal

cat <<'EOF' > src/crc32.ts
import crypto from "node:crypto";
import { CommandType } from "./types.js";

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) =>
      item === undefined ? "null" : canonicalJson(item)
    );
    return `[${items.join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const pairs = keys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`
  );
  return `{${pairs.join(",")}}`;
}

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ data[i]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function computeCommandHash(
  shipmentId: string,
  type: CommandType,
  payload: unknown
): string {
  const canonical = canonicalJson({ payload, shipmentId, type });
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}
EOF

cat <<'EOF' > src/wal.ts
import fs from "node:fs";
import path from "node:path";
import { canonicalJson, crc32 } from "./crc32.js";
import {
  WAL_FILE_HEADER,
  WAL_FRAME_HEADER_BYTES,
  WAL_FRAME_MAGIC,
  WAL_FRAME_VERSION,
  WAL_MAX_PAYLOAD_BYTES,
  WalCommitPayload,
  WalCorruptionError,
  WalFrame,
  WalRecordType,
} from "./types.js";

export interface WalRecoveryResult {
  frames: WalFrame[];
  recoveredTornBytes: number;
  lastValidLsn: bigint;
}

function hasFrameMagicAfter(buf: Buffer, startOffset: number): boolean {
  for (let i = startOffset; i <= buf.length - 4; i++) {
    if (
      buf[i] === 0x53 &&
      buf[i + 1] === 0x48 &&
      buf[i + 2] === 0x50 &&
      buf[i + 3] === 0x57
    ) {
      return true;
    }
  }
  return false;
}

function truncateAndSync(filePath: string, len: number): void {
  const fd = fs.openSync(filePath, "r+");
  try {
    fs.ftruncateSync(fd, len);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function writeHeaderAndSync(filePath: string): void {
  const fd = fs.openSync(filePath, "w");
  try {
    fs.writeFileSync(fd, WAL_FILE_HEADER);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export class BinaryWal {
  public readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  public openAndRecover(baseLsn: bigint = 0n): WalRecoveryResult {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });

    if (!fs.existsSync(this.filePath)) {
      writeHeaderAndSync(this.filePath);
      return { frames: [], recoveredTornBytes: 0, lastValidLsn: baseLsn };
    }

    const buf = fs.readFileSync(this.filePath);
    if (buf.length === 0) {
      writeHeaderAndSync(this.filePath);
      return { frames: [], recoveredTornBytes: 0, lastValidLsn: baseLsn };
    }

    if (buf.length < WAL_FILE_HEADER.length) {
      const expectedPrefix = WAL_FILE_HEADER.subarray(0, buf.length);
      if (buf.equals(expectedPrefix)) {
        writeHeaderAndSync(this.filePath);
        return {
          frames: [],
          recoveredTornBytes: buf.length,
          lastValidLsn: baseLsn,
        };
      }
      throw new WalCorruptionError("Corrupted WAL file header", 0, 0n);
    }

    if (!buf.subarray(0, WAL_FILE_HEADER.length).equals(WAL_FILE_HEADER)) {
      throw new WalCorruptionError("Invalid WAL file header magic or version", 0, 0n);
    }

    const frames: WalFrame[] = [];
    let offset = WAL_FILE_HEADER.length;
    let expectedLsn = baseLsn + 1n;
    let recoveredTornBytes = 0;
    let lastValidLsn = baseLsn;

    while (offset < buf.length) {
      const remaining = buf.length - offset;

      if (remaining < WAL_FRAME_HEADER_BYTES) {
        const magicPrefixLen = Math.min(4, remaining);
        const expectedMagicPrefix = WAL_FILE_HEADER.subarray(0, magicPrefixLen);
        if (!buf.subarray(offset, offset + magicPrefixLen).equals(expectedMagicPrefix)) {
          throw new WalCorruptionError(
            "Invalid frame magic in trailing bytes",
            offset,
            expectedLsn
          );
        }
        recoveredTornBytes = remaining;
        truncateAndSync(this.filePath, offset);
        break;
      }

      const magic = buf.readUInt32BE(offset);
      if (magic !== WAL_FRAME_MAGIC) {
        throw new WalCorruptionError(
          `Invalid frame magic 0x${magic.toString(16)} at offset ${offset}`,
          offset,
          expectedLsn
        );
      }

      const version = buf.readUInt8(offset + 4);
      const recordType = buf.readUInt8(offset + 5);
      const flags = buf.readUInt16BE(offset + 6);
      const lsn = buf.readBigUInt64BE(offset + 8);
      const payloadLen = buf.readUInt32BE(offset + 16);
      const frameCrc32 = buf.readUInt32BE(offset + 20);

      if (
        version !== WAL_FRAME_VERSION ||
        (recordType !== WalRecordType.COMMAND_COMMIT &&
          recordType !== WalRecordType.CHECKPOINT_MARKER) ||
        payloadLen === 0 ||
        payloadLen > WAL_MAX_PAYLOAD_BYTES
      ) {
        throw new WalCorruptionError(
          `Invalid frame header fields at offset ${offset}`,
          offset,
          expectedLsn
        );
      }

      if (offset === WAL_FILE_HEADER.length) {
        if (lsn === 0n || lsn > baseLsn + 1n) {
          throw new WalCorruptionError(
            `Initial frame LSN ${lsn} does not match expected ${baseLsn + 1n}`,
            offset,
            baseLsn + 1n
          );
        }
        expectedLsn = lsn;
      } else if (lsn !== expectedLsn) {
        throw new WalCorruptionError(
          `Non-monotonic LSN ${lsn}, expected ${expectedLsn}`,
          offset,
          expectedLsn
        );
      }

      const frameEnd = offset + WAL_FRAME_HEADER_BYTES + payloadLen;
      if (frameEnd > buf.length) {
        if (hasFrameMagicAfter(buf, offset + WAL_FRAME_HEADER_BYTES)) {
          throw new WalCorruptionError(
            `Truncated frame at offset ${offset} followed by subsequent frame magic`,
            offset,
            expectedLsn
          );
        }
        recoveredTornBytes = buf.length - offset;
        truncateAndSync(this.filePath, offset);
        break;
      }

      const headerSlice = buf.subarray(offset, offset + 20);
      const payloadSlice = buf.subarray(offset + WAL_FRAME_HEADER_BYTES, frameEnd);
      const computedCrc = crc32(Buffer.concat([headerSlice, payloadSlice]));

      let parsedPayload: WalCommitPayload | Record<string, unknown> | null = null;
      let validPayload = computedCrc === frameCrc32;
      if (validPayload) {
        try {
          parsedPayload = JSON.parse(payloadSlice.toString("utf8"));
          if (parsedPayload === null || typeof parsedPayload !== "object") {
            validPayload = false;
          }
        } catch {
          validPayload = false;
        }
      }

      if (!validPayload) {
        if (frameEnd === buf.length) {
          recoveredTornBytes = buf.length - offset;
          truncateAndSync(this.filePath, offset);
          break;
        }
        throw new WalCorruptionError(
          `Mid-log frame corruption (CRC or JSON invalid) at offset ${offset}`,
          offset,
          expectedLsn
        );
      }

      frames.push({
        recordType: recordType as WalRecordType,
        flags,
        lsn,
        payload: parsedPayload!,
        frameOffset: offset,
        frameByteLength: WAL_FRAME_HEADER_BYTES + payloadLen,
        crc32: frameCrc32,
      });

      if (lsn > lastValidLsn) {
        lastValidLsn = lsn;
      }
      offset = frameEnd;
      expectedLsn = lsn + 1n;
    }

    return { frames, recoveredTornBytes, lastValidLsn };
  }

  public appendFrame(
    lsn: bigint,
    payload: WalCommitPayload | Record<string, unknown>,
    recordType: WalRecordType = WalRecordType.COMMAND_COMMIT,
    flags: number = 0
  ): WalFrame {
    const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
    if (payloadBytes.length === 0 || payloadBytes.length > WAL_MAX_PAYLOAD_BYTES) {
      throw new Error(`Invalid WAL payload length: ${payloadBytes.length}`);
    }

    const header = Buffer.alloc(WAL_FRAME_HEADER_BYTES);
    header.writeUInt32BE(WAL_FRAME_MAGIC, 0);
    header.writeUInt8(WAL_FRAME_VERSION, 4);
    header.writeUInt8(recordType, 5);
    header.writeUInt16BE(flags, 6);
    header.writeBigUInt64BE(lsn, 8);
    header.writeUInt32BE(payloadBytes.length, 16);

    const frameCrc = crc32(Buffer.concat([header.subarray(0, 20), payloadBytes]));
    header.writeUInt32BE(frameCrc, 20);

    const frameBuf = Buffer.concat([header, payloadBytes]);
    const fd = fs.openSync(this.filePath, "a");
    let frameOffset = 0;
    try {
      frameOffset = fs.fstatSync(fd).size;
      fs.writeFileSync(fd, frameBuf);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    return {
      recordType,
      flags,
      lsn,
      payload,
      frameOffset,
      frameByteLength: frameBuf.length,
      crc32: frameCrc,
    };
  }

  public rewriteRetainingAfter(cutoffLsn: bigint, framesToRetain: WalFrame[]): void {
    const tmpPath = `${this.filePath}.tmp`;
    const chunks: Buffer[] = [WAL_FILE_HEADER];

    for (const frame of framesToRetain) {
      if (frame.lsn <= cutoffLsn) {
        continue;
      }
      const payloadBytes = Buffer.from(canonicalJson(frame.payload), "utf8");
      const header = Buffer.alloc(WAL_FRAME_HEADER_BYTES);
      header.writeUInt32BE(WAL_FRAME_MAGIC, 0);
      header.writeUInt8(WAL_FRAME_VERSION, 4);
      header.writeUInt8(frame.recordType, 5);
      header.writeUInt16BE(frame.flags, 6);
      header.writeBigUInt64BE(frame.lsn, 8);
      header.writeUInt32BE(payloadBytes.length, 16);
      const frameCrc = crc32(Buffer.concat([header.subarray(0, 20), payloadBytes]));
      header.writeUInt32BE(frameCrc, 20);
      chunks.push(header, payloadBytes);
    }

    const fullBuf = Buffer.concat(chunks);
    const fd = fs.openSync(tmpPath, "w");
    try {
      fs.writeFileSync(fd, fullBuf);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, this.filePath);
  }
}
EOF

cat <<'EOF' > src/snapshot.ts
import fs from "node:fs";
import path from "node:path";
import { canonicalJson, crc32 } from "./crc32.js";
import {
  SNAPSHOT_FILE_HEADER,
  SNAPSHOT_HEADER_BYTES,
  SnapshotCorruptionError,
  SnapshotData,
} from "./types.js";

export class SnapshotStore {
  public readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  public load(): SnapshotData | null {
    if (!fs.existsSync(this.filePath)) {
      return null;
    }

    const buf = fs.readFileSync(this.filePath);
    if (buf.length < SNAPSHOT_HEADER_BYTES) {
      throw new SnapshotCorruptionError(
        `Snapshot file too short (${buf.length} bytes)`,
        0
      );
    }

    if (!buf.subarray(0, 8).equals(SNAPSHOT_FILE_HEADER)) {
      throw new SnapshotCorruptionError("Invalid snapshot magic or version", 0);
    }

    const lastLsn = buf.readBigUInt64BE(8);
    const payloadLen = buf.readUInt32BE(16);
    const snapCrc = buf.readUInt32BE(20);

    if (buf.length !== SNAPSHOT_HEADER_BYTES + payloadLen) {
      throw new SnapshotCorruptionError(
        `Snapshot length mismatch: expected ${SNAPSHOT_HEADER_BYTES + payloadLen}, got ${buf.length}`,
        16
      );
    }

    const headerPrefix = buf.subarray(0, 20);
    const payloadSlice = buf.subarray(SNAPSHOT_HEADER_BYTES);
    const computedCrc = crc32(Buffer.concat([headerPrefix, payloadSlice]));
    if (computedCrc !== snapCrc) {
      throw new SnapshotCorruptionError("Snapshot CRC32 mismatch", 20);
    }

    let parsed: SnapshotData;
    try {
      parsed = JSON.parse(payloadSlice.toString("utf8")) as SnapshotData;
    } catch {
      throw new SnapshotCorruptionError("Invalid JSON in snapshot payload", 24);
    }

    if (
      !parsed ||
      typeof parsed !== "object" ||
      parsed.lastLsn !== lastLsn.toString() ||
      typeof parsed.shipments !== "object" ||
      typeof parsed.idempotencyIndex !== "object"
    ) {
      throw new SnapshotCorruptionError("Malformed snapshot data structure", 24);
    }

    return parsed;
  }

  public saveAtomic(data: SnapshotData): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmpPath = `${this.filePath}.tmp`;

    const payloadBytes = Buffer.from(canonicalJson(data), "utf8");
    const header = Buffer.alloc(SNAPSHOT_HEADER_BYTES);
    SNAPSHOT_FILE_HEADER.copy(header, 0);
    header.writeBigUInt64BE(BigInt(data.lastLsn), 8);
    header.writeUInt32BE(payloadBytes.length, 16);

    const snapCrc = crc32(Buffer.concat([header.subarray(0, 20), payloadBytes]));
    header.writeUInt32BE(snapCrc, 20);

    const fullBuf = Buffer.concat([header, payloadBytes]);
    const fd = fs.openSync(tmpPath, "w");
    try {
      fs.writeFileSync(fd, fullBuf);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    fs.renameSync(tmpPath, this.filePath);
  }
}
EOF

cat <<'EOF' > src/engine.ts
import fs from "node:fs";
import path from "node:path";
import { computeCommandHash } from "./crc32.js";
import { SnapshotStore } from "./snapshot.js";
import {
  CommandExecutionResult,
  CommandType,
  IdempotencyConflictError,
  IdempotencyEntry,
  InvalidTransitionError,
  RecoveryStats,
  ShipmentCommand,
  ShipmentRecord,
  ValidationError,
  WalCommitPayload,
  WalFrame,
  WalRecordType,
} from "./types.js";
import { BinaryWal } from "./wal.js";

const VALID_COMMAND_TYPES = new Set<CommandType>([
  "CREATE",
  "BOOK",
  "DISPATCH",
  "HOLD",
  "RESUME",
  "DELIVER",
  "CANCEL",
]);

function isNonEmptyString(val: unknown): val is string {
  return typeof val === "string" && val.trim().length > 0;
}

function isSafeNonNegativeInt(val: unknown): val is number {
  return typeof val === "number" && Number.isSafeInteger(val) && val >= 0;
}

export class ShipmentEngine {
  public readonly dataDir: string;
  private readonly wal: BinaryWal;
  private readonly snapshotStore: SnapshotStore;
  private shipments: Map<string, ShipmentRecord> = new Map();
  private idempotencyIndex: Map<string, IdempotencyEntry> = new Map();
  private committedFrames: WalFrame[] = [];
  private currentLsn: bigint = 0n;
  private recoveryStats: RecoveryStats = {
    replayedFrames: 0,
    recoveredTornBytes: 0,
    snapshotLoaded: false,
    snapshotLastLsn: 0n,
    currentLsn: 0n,
  };

  private constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.wal = new BinaryWal(path.join(dataDir, "wal.bin"));
    this.snapshotStore = new SnapshotStore(path.join(dataDir, "snapshot.bin"));
  }

  public static open(dataDir: string): ShipmentEngine {
    fs.mkdirSync(dataDir, { recursive: true });

    // Clean up any leftover temporary files from interrupted compactions
    for (const tmpName of ["snapshot.bin.tmp", "wal.bin.tmp"]) {
      const p = path.join(dataDir, tmpName);
      if (fs.existsSync(p)) {
        fs.rmSync(p, { force: true });
      }
    }

    const engine = new ShipmentEngine(dataDir);
    engine.recover();
    return engine;
  }

  private recover(): void {
    const snap = this.snapshotStore.load();
    let baseLsn = 0n;
    if (snap) {
      baseLsn = BigInt(snap.lastLsn);
      this.currentLsn = baseLsn;
      for (const [sid, rec] of Object.entries(snap.shipments)) {
        this.shipments.set(sid, structuredClone(rec));
      }
      for (const [cid, entry] of Object.entries(snap.idempotencyIndex)) {
        this.idempotencyIndex.set(cid, structuredClone(entry));
      }
    }

    const walResult = this.wal.openAndRecover(baseLsn);
    let replayedCount = 0;
    const retainedFrames: WalFrame[] = [];

    for (const frame of walResult.frames) {
      if (frame.lsn <= baseLsn) {
        continue;
      }
      if (frame.recordType === WalRecordType.COMMAND_COMMIT) {
        const commitPayload = frame.payload as WalCommitPayload;
        const shipmentClone = structuredClone(commitPayload.shipment);
        this.shipments.set(shipmentClone.shipmentId, shipmentClone);
        this.idempotencyIndex.set(commitPayload.command.commandId, {
          commandId: commitPayload.command.commandId,
          commandHash: commitPayload.commandHash,
          lsn: commitPayload.lsn,
          resultSnapshot: structuredClone(shipmentClone),
        });
      }
      this.currentLsn = frame.lsn;
      retainedFrames.push(frame);
      replayedCount++;
    }

    this.committedFrames = retainedFrames;
    this.recoveryStats = {
      replayedFrames: replayedCount,
      recoveredTornBytes: walResult.recoveredTornBytes,
      snapshotLoaded: snap !== null,
      snapshotLastLsn: baseLsn,
      currentLsn: this.currentLsn,
    };
  }

  public getRecoveryStats(): RecoveryStats {
    return { ...this.recoveryStats };
  }

  public getCurrentLsn(): bigint {
    return this.currentLsn;
  }

  public getShipment(shipmentId: string): ShipmentRecord | null {
    const rec = this.shipments.get(shipmentId);
    return rec ? structuredClone(rec) : null;
  }

  public listShipments(): ShipmentRecord[] {
    return Array.from(this.shipments.values())
      .sort((a, b) => (a.shipmentId < b.shipmentId ? -1 : a.shipmentId > b.shipmentId ? 1 : 0))
      .map((r) => structuredClone(r));
  }

  public executeCommand(cmd: ShipmentCommand): CommandExecutionResult {
    if (!cmd || typeof cmd !== "object") {
      throw new ValidationError("Command must be an object");
    }
    if (!isNonEmptyString(cmd.commandId)) {
      throw new ValidationError("commandId must be a non-empty string");
    }
    if (!isNonEmptyString(cmd.shipmentId)) {
      throw new ValidationError("shipmentId must be a non-empty string");
    }
    if (!VALID_COMMAND_TYPES.has(cmd.type)) {
      throw new ValidationError(`Invalid command type: ${String(cmd.type)}`);
    }
    if (!cmd.payload || typeof cmd.payload !== "object" || Array.isArray(cmd.payload)) {
      throw new ValidationError("payload must be a plain object");
    }

    const commandHash = computeCommandHash(cmd.shipmentId, cmd.type, cmd.payload);
    const existingIdem = this.idempotencyIndex.get(cmd.commandId);
    if (existingIdem) {
      if (existingIdem.commandHash === commandHash) {
        return {
          lsn: BigInt(existingIdem.lsn),
          shipment: structuredClone(existingIdem.resultSnapshot),
          deduplicated: true,
        };
      }
      throw new IdempotencyConflictError(
        `Idempotency conflict for commandId ${cmd.commandId}`,
        cmd.commandId
      );
    }

    if (!isSafeNonNegativeInt(cmd.timestamp)) {
      throw new ValidationError("timestamp must be a non-negative safe integer");
    }

    const current = this.shipments.get(cmd.shipmentId) ?? null;
    if (current && cmd.timestamp < current.updatedAtTs) {
      throw new ValidationError(
        `Command timestamp ${cmd.timestamp} is earlier than shipment updatedAtTs ${current.updatedAtTs}`
      );
    }

    const nextLsn = this.currentLsn + 1n;
    const updatedShipment = this.applyTransition(cmd, current, nextLsn);

    const walPayload: WalCommitPayload = {
      command: {
        commandId: cmd.commandId,
        shipmentId: cmd.shipmentId,
        type: cmd.type,
        timestamp: cmd.timestamp,
        payload: structuredClone(cmd.payload),
      },
      commandHash,
      lsn: nextLsn.toString(),
      shipment: updatedShipment,
    };

    const frame = this.wal.appendFrame(
      nextLsn,
      walPayload,
      WalRecordType.COMMAND_COMMIT,
      0
    );

    this.currentLsn = nextLsn;
    this.shipments.set(cmd.shipmentId, structuredClone(updatedShipment));
    this.idempotencyIndex.set(cmd.commandId, {
      commandId: cmd.commandId,
      commandHash,
      lsn: nextLsn.toString(),
      resultSnapshot: structuredClone(updatedShipment),
    });
    this.committedFrames.push(frame);
    this.recoveryStats.currentLsn = this.currentLsn;

    return {
      lsn: nextLsn,
      shipment: structuredClone(updatedShipment),
      deduplicated: false,
    };
  }

  private applyTransition(
    cmd: ShipmentCommand,
    current: ShipmentRecord | null,
    assignedLsn: bigint
  ): ShipmentRecord {
    const p = cmd.payload;

    switch (cmd.type) {
      case "CREATE": {
        if (current !== null) {
          throw new InvalidTransitionError(
            `Shipment ${cmd.shipmentId} already exists in state ${current.state}`,
            cmd.shipmentId,
            current.state,
            cmd.type
          );
        }
        const origin = p.origin;
        const destination = p.destination;
        const weightKg = p.weightKg;
        const declaredValueCents = p.declaredValueCents;

        if (!isNonEmptyString(origin) || !isNonEmptyString(destination)) {
          throw new ValidationError("origin and destination must be non-empty strings");
        }
        if (origin === destination) {
          throw new ValidationError("origin and destination must be different");
        }
        if (typeof weightKg !== "number" || !Number.isFinite(weightKg) || weightKg <= 0) {
          throw new ValidationError("weightKg must be a finite positive number");
        }
        if (!isSafeNonNegativeInt(declaredValueCents)) {
          throw new ValidationError("declaredValueCents must be a non-negative safe integer");
        }

        return {
          shipmentId: cmd.shipmentId,
          state: "CREATED",
          version: 1,
          origin,
          destination,
          weightKg,
          declaredValueCents,
          createdAtTs: cmd.timestamp,
          updatedAtTs: cmd.timestamp,
          lastCommandId: cmd.commandId,
          lastLsn: assignedLsn.toString(),
          carrierId: null,
          vesselOrFlight: null,
          scheduledDepartureTs: null,
          departedAtTs: null,
          originPort: null,
          heldFromState: null,
          holdReason: null,
          heldAtTs: null,
          resumedAtTs: null,
          clearanceRef: null,
          deliveredAtTs: null,
          receiverSignature: null,
          cancelledAtTs: null,
          cancelReason: null,
        };
      }

      case "BOOK": {
        if (!current || current.state !== "CREATED") {
          throw new InvalidTransitionError(
            `Cannot BOOK shipment ${cmd.shipmentId} from state ${current?.state ?? "null"}`,
            cmd.shipmentId,
            current?.state ?? null,
            cmd.type
          );
        }
        const carrierId = p.carrierId;
        const vesselOrFlight = p.vesselOrFlight;
        const scheduledDepartureTs = p.scheduledDepartureTs;

        if (!isNonEmptyString(carrierId) || !isNonEmptyString(vesselOrFlight)) {
          throw new ValidationError("carrierId and vesselOrFlight must be non-empty strings");
        }
        if (
          !isSafeNonNegativeInt(scheduledDepartureTs) ||
          scheduledDepartureTs < current.createdAtTs
        ) {
          throw new ValidationError(
            "scheduledDepartureTs must be an integer >= shipment.createdAtTs"
          );
        }

        return {
          ...structuredClone(current),
          state: "BOOKED",
          version: current.version + 1,
          updatedAtTs: cmd.timestamp,
          lastCommandId: cmd.commandId,
          lastLsn: assignedLsn.toString(),
          carrierId,
          vesselOrFlight,
          scheduledDepartureTs,
        };
      }

      case "DISPATCH": {
        if (!current || current.state !== "BOOKED") {
          throw new InvalidTransitionError(
            `Cannot DISPATCH shipment ${cmd.shipmentId} from state ${current?.state ?? "null"}`,
            cmd.shipmentId,
            current?.state ?? null,
            cmd.type
          );
        }
        const departedAtTs = p.departedAtTs;
        const originPort = p.originPort;

        if (!isNonEmptyString(originPort)) {
          throw new ValidationError("originPort must be a non-empty string");
        }
        if (
          !isSafeNonNegativeInt(departedAtTs) ||
          departedAtTs < current.scheduledDepartureTs! ||
          departedAtTs > cmd.timestamp
        ) {
          throw new ValidationError(
            "departedAtTs must be between scheduledDepartureTs and command timestamp"
          );
        }

        return {
          ...structuredClone(current),
          state: "IN_TRANSIT",
          version: current.version + 1,
          updatedAtTs: cmd.timestamp,
          lastCommandId: cmd.commandId,
          lastLsn: assignedLsn.toString(),
          departedAtTs,
          originPort,
        };
      }

      case "HOLD": {
        if (!current || (current.state !== "BOOKED" && current.state !== "IN_TRANSIT")) {
          throw new InvalidTransitionError(
            `Cannot HOLD shipment ${cmd.shipmentId} from state ${current?.state ?? "null"}`,
            cmd.shipmentId,
            current?.state ?? null,
            cmd.type
          );
        }
        const reasonCode = p.reasonCode;
        const heldAtTs = p.heldAtTs;

        if (!isNonEmptyString(reasonCode)) {
          throw new ValidationError("reasonCode must be a non-empty string");
        }
        if (
          !isSafeNonNegativeInt(heldAtTs) ||
          heldAtTs < current.updatedAtTs ||
          heldAtTs > cmd.timestamp
        ) {
          throw new ValidationError(
            "heldAtTs must be between shipment.updatedAtTs and command timestamp"
          );
        }

        return {
          ...structuredClone(current),
          state: "HELD",
          version: current.version + 1,
          updatedAtTs: cmd.timestamp,
          lastCommandId: cmd.commandId,
          lastLsn: assignedLsn.toString(),
          heldFromState: current.state,
          holdReason: reasonCode,
          heldAtTs,
        };
      }

      case "RESUME": {
        if (!current || current.state !== "HELD" || !current.heldFromState) {
          throw new InvalidTransitionError(
            `Cannot RESUME shipment ${cmd.shipmentId} from state ${current?.state ?? "null"}`,
            cmd.shipmentId,
            current?.state ?? null,
            cmd.type
          );
        }
        const resumedAtTs = p.resumedAtTs;
        const clearanceRef = p.clearanceRef;

        if (!isNonEmptyString(clearanceRef)) {
          throw new ValidationError("clearanceRef must be a non-empty string");
        }
        if (
          !isSafeNonNegativeInt(resumedAtTs) ||
          resumedAtTs < current.heldAtTs! ||
          resumedAtTs > cmd.timestamp
        ) {
          throw new ValidationError(
            "resumedAtTs must be between heldAtTs and command timestamp"
          );
        }

        return {
          ...structuredClone(current),
          state: current.heldFromState,
          version: current.version + 1,
          updatedAtTs: cmd.timestamp,
          lastCommandId: cmd.commandId,
          lastLsn: assignedLsn.toString(),
          heldFromState: null,
          holdReason: null,
          resumedAtTs,
          clearanceRef,
        };
      }

      case "DELIVER": {
        if (!current || current.state !== "IN_TRANSIT") {
          throw new InvalidTransitionError(
            `Cannot DELIVER shipment ${cmd.shipmentId} from state ${current?.state ?? "null"}`,
            cmd.shipmentId,
            current?.state ?? null,
            cmd.type
          );
        }
        const deliveredAtTs = p.deliveredAtTs;
        const receiverSignature = p.receiverSignature;

        if (!isNonEmptyString(receiverSignature)) {
          throw new ValidationError("receiverSignature must be a non-empty string");
        }
        if (
          !isSafeNonNegativeInt(deliveredAtTs) ||
          deliveredAtTs < current.departedAtTs! ||
          deliveredAtTs > cmd.timestamp
        ) {
          throw new ValidationError(
            "deliveredAtTs must be between departedAtTs and command timestamp"
          );
        }

        return {
          ...structuredClone(current),
          state: "DELIVERED",
          version: current.version + 1,
          updatedAtTs: cmd.timestamp,
          lastCommandId: cmd.commandId,
          lastLsn: assignedLsn.toString(),
          deliveredAtTs,
          receiverSignature,
        };
      }

      case "CANCEL": {
        if (
          !current ||
          (current.state !== "CREATED" &&
            current.state !== "BOOKED" &&
            current.state !== "HELD")
        ) {
          throw new InvalidTransitionError(
            `Cannot CANCEL shipment ${cmd.shipmentId} from state ${current?.state ?? "null"}`,
            cmd.shipmentId,
            current?.state ?? null,
            cmd.type
          );
        }
        const cancelledAtTs = p.cancelledAtTs;
        const reason = p.reason;

        if (!isNonEmptyString(reason)) {
          throw new ValidationError("reason must be a non-empty string");
        }
        if (
          !isSafeNonNegativeInt(cancelledAtTs) ||
          cancelledAtTs < current.updatedAtTs ||
          cancelledAtTs > cmd.timestamp
        ) {
          throw new ValidationError(
            "cancelledAtTs must be between shipment.updatedAtTs and command timestamp"
          );
        }

        return {
          ...structuredClone(current),
          state: "CANCELLED",
          version: current.version + 1,
          updatedAtTs: cmd.timestamp,
          lastCommandId: cmd.commandId,
          lastLsn: assignedLsn.toString(),
          heldFromState: null,
          holdReason: null,
          cancelledAtTs,
          cancelReason: reason,
        };
      }

      default:
        throw new ValidationError(`Unsupported command type: ${String(cmd.type)}`);
    }
  }

  public compact(): void {
    this.compactUpTo(this.currentLsn);
  }

  public compactUpTo(targetLsn: bigint): void {
    if (targetLsn < 0n || targetLsn > this.currentLsn) {
      throw new ValidationError(
        `targetLsn ${targetLsn} out of range [0, ${this.currentLsn}]`
      );
    }

    const baseSnap = this.snapshotStore.load();
    const baseLsn = baseSnap ? BigInt(baseSnap.lastLsn) : 0n;
    if (targetLsn < baseLsn) {
      throw new ValidationError(
        `targetLsn ${targetLsn} cannot be less than existing snapshot lastLsn ${baseLsn}`
      );
    }

    // Reconstruct state at targetLsn from baseSnap + committedFrames with lsn <= targetLsn
    const snapShipments: Record<string, ShipmentRecord> = {};
    const snapIdem: Record<string, IdempotencyEntry> = {};

    if (baseSnap) {
      for (const [k, v] of Object.entries(baseSnap.shipments)) {
        snapShipments[k] = structuredClone(v);
      }
      for (const [k, v] of Object.entries(baseSnap.idempotencyIndex)) {
        snapIdem[k] = structuredClone(v);
      }
    }

    const remainingFrames: WalFrame[] = [];
    for (const frame of this.committedFrames) {
      if (frame.lsn <= targetLsn) {
        if (frame.recordType === WalRecordType.COMMAND_COMMIT) {
          const cp = frame.payload as WalCommitPayload;
          snapShipments[cp.shipment.shipmentId] = structuredClone(cp.shipment);
          snapIdem[cp.command.commandId] = {
            commandId: cp.command.commandId,
            commandHash: cp.commandHash,
            lsn: cp.lsn,
            resultSnapshot: structuredClone(cp.shipment),
          };
        }
      } else {
        remainingFrames.push(frame);
      }
    }

    this.snapshotStore.saveAtomic({
      lastLsn: targetLsn.toString(),
      shipments: snapShipments,
      idempotencyIndex: snapIdem,
    });

    this.wal.rewriteRetainingAfter(targetLsn, remainingFrames);
    this.committedFrames = remainingFrames;
  }
}
EOF

./build_and_test.sh
