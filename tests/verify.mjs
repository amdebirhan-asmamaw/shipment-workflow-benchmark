import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const REWARD_TXT = "/logs/verifier/reward.txt";
const DETAILS_JSON = "/logs/verifier/details.json";

function writeReward(score, details) {
  const clamped = Math.max(0, Math.min(1, Number(score) || 0));
  const formatted = clamped.toFixed(3);
  fs.mkdirSync("/logs/verifier", { recursive: true });
  fs.writeFileSync(REWARD_TXT, `${formatted}\n`, "utf8");
  fs.writeFileSync(
    DETAILS_JSON,
    JSON.stringify({ reward: Number(formatted), ...details }, null, 2) + "\n",
    "utf8"
  );
  console.log(`\n[verifier] Final Score: ${formatted}`);
}

function refCrc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function refCanonicalJson(val) {
  if (val === null || typeof val !== "object") {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    return "[" + val.map((item) => refCanonicalJson(item === undefined ? null : item)).join(",") + "]";
  }
  const keys = Object.keys(val)
    .filter((k) => val[k] !== undefined)
    .sort();
  return (
    "{" +
    keys
      .map((k) => `${JSON.stringify(k)}:${refCanonicalJson(val[k])}`)
      .join(",") +
    "}"
  );
}

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fswe-verify-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
  let mod;
  try {
    mod = await import("file:///app/shipment-wal/dist/index.js");
  } catch (err) {
    writeReward(0, { error: `Failed to import /app/shipment-wal/dist/index.js: ${err.message}` });
    return;
  }

  const {
    ShipmentEngine,
    crc32,
    canonicalJson,
    computeCommandHash,
    WalCorruptionError,
    SnapshotCorruptionError,
    IdempotencyConflictError,
    InvalidTransitionError,
    ValidationError,
  } = mod;

  const suites = [
    {
      name: "suite_01_wal_framing",
      weight: 0.15,
      fn: () => {
        // 1. CRC32 vectors
        assert.equal(crc32(Buffer.from("123456789", "utf8")), 0xcbf43926);
        assert.equal(crc32(Buffer.alloc(0)), 0x00000000);
        const sample = Buffer.from("SHPWWAL-frame-check-payload", "utf8");
        assert.equal(crc32(sample), refCrc32(sample));

        // 2. Canonical JSON & SHA-256 hash
        const nestedA = { z: [3, { b: 2, a: 1 }], a: "hello", u: undefined };
        const nestedB = { a: "hello", z: [3, { a: 1, b: 2 }] };
        assert.equal(canonicalJson(nestedA), '{"a":"hello","z":[3,{"a":1,"b":2}]}');
        assert.equal(canonicalJson(nestedA), canonicalJson(nestedB));

        const expectedHash = crypto
          .createHash("sha256")
          .update(refCanonicalJson({ payload: { b: 2, a: 1 }, shipmentId: "S1", type: "CREATE" }), "utf8")
          .digest("hex");
        assert.equal(computeCommandHash("S1", "CREATE", { a: 1, b: 2 }), expectedHash);

        // 3. White-box WAL binary format check
        withTempDir((dir) => {
          const engine = ShipmentEngine.open(dir);
          engine.executeCommand({
            commandId: "c1",
            shipmentId: "SHP-01",
            type: "CREATE",
            timestamp: 1000,
            payload: { origin: "SIN", destination: "RTM", weightKg: 500, declaredValueCents: 95000 },
          });
          engine.executeCommand({
            commandId: "c2",
            shipmentId: "SHP-01",
            type: "BOOK",
            timestamp: 1100,
            payload: { carrierId: "MAERSK", vesselOrFlight: "V-101", scheduledDepartureTs: 1200 },
          });
          engine.executeCommand({
            commandId: "c3",
            shipmentId: "SHP-01",
            type: "DISPATCH",
            timestamp: 1250,
            payload: { departedAtTs: 1210, originPort: "SIN-TERM-2" },
          });

          const walPath = path.join(dir, "wal.bin");
          assert.ok(fs.existsSync(walPath), "wal.bin must exist on disk");
          const buf = fs.readFileSync(walPath);

          // Check 8-byte header
          assert.equal(buf.subarray(0, 8).toString("binary"), "SHPWWAL\x01");

          let offset = 8;
          let expectedLsn = 1n;
          while (offset < buf.length) {
            assert.ok(buf.length - offset >= 24, "Full 24-byte frame header must exist");
            const magic = buf.readUInt32BE(offset);
            const version = buf.readUInt8(offset + 4);
            const recordType = buf.readUInt8(offset + 5);
            const flags = buf.readUInt16BE(offset + 6);
            const lsn = buf.readBigUInt64BE(offset + 8);
            const payloadLen = buf.readUInt32BE(offset + 16);
            const frameCrc = buf.readUInt32BE(offset + 20);

            assert.equal(magic, 0x53485057);
            assert.equal(version, 1);
            assert.equal(recordType, 1);
            assert.equal(flags, 0);
            assert.equal(lsn, expectedLsn);
            assert.ok(payloadLen > 0 && offset + 24 + payloadLen <= buf.length);

            const crcInput = Buffer.concat([
              buf.subarray(offset, offset + 20),
              buf.subarray(offset + 24, offset + 24 + payloadLen),
            ]);
            assert.equal(frameCrc, refCrc32(crcInput), `CRC32 mismatch at LSN ${lsn}`);

            const payloadStr = buf.subarray(offset + 24, offset + 24 + payloadLen).toString("utf8");
            const parsed = JSON.parse(payloadStr);
            assert.equal(payloadStr, refCanonicalJson(parsed), "WAL frame payload must be canonical JSON");
            assert.equal(parsed.lsn, expectedLsn.toString());

            offset += 24 + payloadLen;
            expectedLsn += 1n;
          }
          assert.equal(expectedLsn, 4n, "Must have decoded exactly 3 frames");
        });
      },
    },
    {
      name: "suite_02_torn_tail_recovery",
      weight: 0.15,
      fn: () => {
        // Case 1: Torn 4-byte file header prefix
        withTempDir((dir) => {
          const walPath = path.join(dir, "wal.bin");
          fs.writeFileSync(walPath, Buffer.from("SHPW", "binary"));
          const engine = ShipmentEngine.open(dir);
          assert.equal(engine.getCurrentLsn(), 0n);
          assert.equal(fs.readFileSync(walPath).subarray(0, 8).toString("binary"), "SHPWWAL\x01");
        });

        // Case 2: Torn frame header at EOF (11 bytes appended)
        withTempDir((dir) => {
          const engine = ShipmentEngine.open(dir);
          engine.executeCommand({
            commandId: "c1",
            shipmentId: "SHP-T1",
            type: "CREATE",
            timestamp: 1000,
            payload: { origin: "LAX", destination: "NRT", weightKg: 100, declaredValueCents: 10000 },
          });
          engine.executeCommand({
            commandId: "c2",
            shipmentId: "SHP-T1",
            type: "BOOK",
            timestamp: 1100,
            payload: { carrierId: "ANA", vesselOrFlight: "NH105", scheduledDepartureTs: 1200 },
          });

          const walPath = path.join(dir, "wal.bin");
          const validSize = fs.statSync(walPath).size;
          const partialHeader = Buffer.from([0x53, 0x48, 0x50, 0x57, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03]);
          fs.appendFileSync(walPath, partialHeader);

          const recovered = ShipmentEngine.open(dir);
          const stats = recovered.getRecoveryStats();
          assert.equal(stats.recoveredTornBytes, partialHeader.length);
          assert.equal(stats.replayedFrames, 2);
          assert.equal(recovered.getCurrentLsn(), 2n);
          assert.equal(fs.statSync(walPath).size, validSize);

          // Case 3: Torn payload at EOF (valid 24B header for LSN 3 claiming 150B payload, only 40B present)
          const fakeHeader = Buffer.alloc(24);
          fakeHeader.writeUInt32BE(0x53485057, 0);
          fakeHeader.writeUInt8(1, 4);
          fakeHeader.writeUInt8(1, 5);
          fakeHeader.writeUInt16BE(0, 6);
          fakeHeader.writeBigUInt64BE(3n, 8);
          fakeHeader.writeUInt32BE(150, 16);
          fakeHeader.writeUInt32BE(0x12345678, 20);
          const partialPayload = Buffer.alloc(40, 0x7b);
          fs.appendFileSync(walPath, Buffer.concat([fakeHeader, partialPayload]));

          const recovered2 = ShipmentEngine.open(dir);
          assert.equal(recovered2.getRecoveryStats().recoveredTornBytes, 64);
          assert.equal(recovered2.getCurrentLsn(), 2n);
          assert.equal(fs.statSync(walPath).size, validSize);

          // Case 4: Corrupted CRC32 on the final frame at exact EOF
          recovered2.executeCommand({
            commandId: "c3",
            shipmentId: "SHP-T1",
            type: "DISPATCH",
            timestamp: 1300,
            payload: { departedAtTs: 1250, originPort: "LAX" },
          });
          const sizeWith3 = fs.statSync(walPath).size;
          const frame3Len = sizeWith3 - validSize;
          const raw = fs.readFileSync(walPath);
          raw[raw.length - 1] ^= 0xff; // Flip last byte of final frame
          fs.writeFileSync(walPath, raw);

          const recovered3 = ShipmentEngine.open(dir);
          assert.equal(recovered3.getRecoveryStats().recoveredTornBytes, frame3Len);
          assert.equal(recovered3.getCurrentLsn(), 2n);
          assert.equal(fs.statSync(walPath).size, validSize);
          assert.equal(recovered3.getShipment("SHP-T1").state, "BOOKED");

          // Subsequent write must cleanly reuse LSN 3
          const r3 = recovered3.executeCommand({
            commandId: "c3-retry",
            shipmentId: "SHP-T1",
            type: "DISPATCH",
            timestamp: 1300,
            payload: { departedAtTs: 1250, originPort: "LAX" },
          });
          assert.equal(r3.lsn, 3n);
          assert.equal(r3.shipment.state, "IN_TRANSIT");
        });
      },
    },
    {
      name: "suite_03_midlog_corruption",
      weight: 0.15,
      fn: () => {
        // 1. Corrupted file header
        withTempDir((dir) => {
          const walPath = path.join(dir, "wal.bin");
          fs.writeFileSync(walPath, Buffer.from("CORRUPT!", "utf8"));
          assert.throws(
            () => ShipmentEngine.open(dir),
            (err) => err instanceof WalCorruptionError && err.offset === 0
          );
        });

        // 2. Mid-log bit flip (frame 1 corrupted while frame 2 & 3 follow)
        withTempDir((dir) => {
          const engine = ShipmentEngine.open(dir);
          for (let i = 1; i <= 3; i++) {
            engine.executeCommand({
              commandId: `cmd-${i}`,
              shipmentId: `SHP-${i}`,
              type: "CREATE",
              timestamp: 1000 + i,
              payload: { origin: "JFK", destination: "LHR", weightKg: 50 * i, declaredValueCents: 1000 * i },
            });
          }
          const walPath = path.join(dir, "wal.bin");
          const origBuf = fs.readFileSync(walPath);
          const f1PayloadLen = origBuf.readUInt32BE(8 + 16);
          const f2Offset = 8 + 24 + f1PayloadLen;

          // Corrupt a byte inside frame 1 payload
          const badMid = Buffer.from(origBuf);
          badMid[8 + 24 + 5] ^= 0x40;
          fs.writeFileSync(walPath, badMid);

          assert.throws(
            () => ShipmentEngine.open(dir),
            (err) => err instanceof WalCorruptionError && err.offset === 8
          );
          assert.equal(fs.statSync(walPath).size, origBuf.length, "Mid-log corruption must not truncate wal.bin");

          // 3. Corrupt frame 2 magic
          const badMagic = Buffer.from(origBuf);
          badMagic.writeUInt32BE(0xdeadbeef, f2Offset);
          fs.writeFileSync(walPath, badMagic);
          assert.throws(
            () => ShipmentEngine.open(dir),
            (err) => err instanceof WalCorruptionError && err.offset === f2Offset
          );

          // 4. LSN gap in frame 2 (set LSN = 9n and recompute valid CRC32)
          const badLsn = Buffer.from(origBuf);
          const f2PayloadLen = badLsn.readUInt32BE(f2Offset + 16);
          badLsn.writeBigUInt64BE(9n, f2Offset + 8);
          const f2CrcInput = Buffer.concat([
            badLsn.subarray(f2Offset, f2Offset + 20),
            badLsn.subarray(f2Offset + 24, f2Offset + 24 + f2PayloadLen),
          ]);
          badLsn.writeUInt32BE(refCrc32(f2CrcInput), f2Offset + 20);
          fs.writeFileSync(walPath, badLsn);

          assert.throws(
            () => ShipmentEngine.open(dir),
            (err) => err instanceof WalCorruptionError && err.offset === f2Offset
          );
        });
      },
    },
    {
      name: "suite_04_state_machine",
      weight: 0.15,
      fn: () => {
        withTempDir((dir) => {
          const engine = ShipmentEngine.open(dir);

          // Happy path with HOLD/RESUME in both BOOKED and IN_TRANSIT
          engine.executeCommand({
            commandId: "s1-create",
            shipmentId: "SHP-SM1",
            type: "CREATE",
            timestamp: 100,
            payload: { origin: "DXB", destination: "FRA", weightKg: 120, declaredValueCents: 450000 },
          });
          engine.executeCommand({
            commandId: "s1-book",
            shipmentId: "SHP-SM1",
            type: "BOOK",
            timestamp: 200,
            payload: { carrierId: "EK", vesselOrFlight: "EK043", scheduledDepartureTs: 300 },
          });
          // Hold from BOOKED
          let res = engine.executeCommand({
            commandId: "s1-hold1",
            shipmentId: "SHP-SM1",
            type: "HOLD",
            timestamp: 250,
            payload: { reasonCode: "DOC_CHECK", heldAtTs: 240 },
          });
          assert.equal(res.shipment.state, "HELD");
          assert.equal(res.shipment.heldFromState, "BOOKED");

          // Resume back to BOOKED
          res = engine.executeCommand({
            commandId: "s1-resume1",
            shipmentId: "SHP-SM1",
            type: "RESUME",
            timestamp: 280,
            payload: { resumedAtTs: 270, clearanceRef: "CLR-1" },
          });
          assert.equal(res.shipment.state, "BOOKED");
          assert.equal(res.shipment.heldFromState, null);

          // Dispatch to IN_TRANSIT
          res = engine.executeCommand({
            commandId: "s1-dispatch",
            shipmentId: "SHP-SM1",
            type: "DISPATCH",
            timestamp: 350,
            payload: { departedAtTs: 310, originPort: "DXB-CARGO" },
          });
          assert.equal(res.shipment.state, "IN_TRANSIT");

          // Cannot CANCEL from IN_TRANSIT
          const lsnBeforeInvalid = engine.getCurrentLsn();
          const walSizeBeforeInvalid = fs.statSync(path.join(dir, "wal.bin")).size;
          assert.throws(
            () =>
              engine.executeCommand({
                commandId: "s1-bad-cancel",
                shipmentId: "SHP-SM1",
                type: "CANCEL",
                timestamp: 360,
                payload: { cancelledAtTs: 355, reason: "TOO_LATE" },
              }),
            InvalidTransitionError
          );
          assert.equal(engine.getCurrentLsn(), lsnBeforeInvalid);
          assert.equal(fs.statSync(path.join(dir, "wal.bin")).size, walSizeBeforeInvalid);

          // Hold from IN_TRANSIT
          res = engine.executeCommand({
            commandId: "s1-hold2",
            shipmentId: "SHP-SM1",
            type: "HOLD",
            timestamp: 400,
            payload: { reasonCode: "CUSTOMS_INSPECTION", heldAtTs: 390 },
          });
          assert.equal(res.shipment.state, "HELD");
          assert.equal(res.shipment.heldFromState, "IN_TRANSIT");

          // Resume back to IN_TRANSIT
          res = engine.executeCommand({
            commandId: "s1-resume2",
            shipmentId: "SHP-SM1",
            type: "RESUME",
            timestamp: 450,
            payload: { resumedAtTs: 440, clearanceRef: "CLR-2" },
          });
          assert.equal(res.shipment.state, "IN_TRANSIT");

          // Deliver
          res = engine.executeCommand({
            commandId: "s1-deliver",
            shipmentId: "SHP-SM1",
            type: "DELIVER",
            timestamp: 500,
            payload: { deliveredAtTs: 490, receiverSignature: "J.DOE" },
          });
          assert.equal(res.shipment.state, "DELIVERED");
          assert.equal(res.shipment.version, 8);

          // Terminal state rejects further commands
          assert.throws(
            () =>
              engine.executeCommand({
                commandId: "s1-after-deliver",
                shipmentId: "SHP-SM1",
                type: "HOLD",
                timestamp: 600,
                payload: { reasonCode: "LATE", heldAtTs: 550 },
              }),
            InvalidTransitionError
          );

          // Validation errors (same origin/destination, negative weight, timestamp regression)
          assert.throws(
            () =>
              engine.executeCommand({
                commandId: "v-bad-1",
                shipmentId: "SHP-BAD",
                type: "CREATE",
                timestamp: 100,
                payload: { origin: "ADD", destination: "ADD", weightKg: 10, declaredValueCents: 100 },
              }),
            ValidationError
          );
          assert.equal(engine.getShipment("SHP-BAD"), null);
        });
      },
    },
    {
      name: "suite_05_idempotency",
      weight: 0.15,
      fn: () => {
        withTempDir((dir) => {
          const engine = ShipmentEngine.open(dir);

          const c1 = engine.executeCommand({
            commandId: "idem-1",
            shipmentId: "SHP-IDEM",
            type: "CREATE",
            timestamp: 1000,
            payload: { origin: "HKG", destination: "SFO", weightKg: 88, declaredValueCents: 200000 },
          });
          assert.equal(c1.deduplicated, false);
          assert.equal(c1.lsn, 1n);

          // Advance state to BOOKED
          engine.executeCommand({
            commandId: "idem-2",
            shipmentId: "SHP-IDEM",
            type: "BOOK",
            timestamp: 1100,
            payload: { carrierId: "CX", vesselOrFlight: "CX870", scheduledDepartureTs: 1200 },
          });
          const walSizeAfter2 = fs.statSync(path.join(dir, "wal.bin")).size;

          // Replay idem-1 with different key order and different timestamp:
          // Must return the historical snapshot at LSN 1 (state: CREATED, version: 1) and deduplicated: true!
          const replay1 = engine.executeCommand({
            commandId: "idem-1",
            shipmentId: "SHP-IDEM",
            type: "CREATE",
            timestamp: 9999,
            payload: { declaredValueCents: 200000, weightKg: 88, destination: "SFO", origin: "HKG" },
          });
          assert.equal(replay1.deduplicated, true);
          assert.equal(replay1.lsn, 1n);
          assert.equal(replay1.shipment.state, "CREATED");
          assert.equal(replay1.shipment.version, 1);
          assert.equal(engine.getCurrentLsn(), 2n);
          assert.equal(fs.statSync(path.join(dir, "wal.bin")).size, walSizeAfter2);

          // Conflict on idem-1 with modified weightKg
          assert.throws(
            () =>
              engine.executeCommand({
                commandId: "idem-1",
                shipmentId: "SHP-IDEM",
                type: "CREATE",
                timestamp: 1000,
                payload: { origin: "HKG", destination: "SFO", weightKg: 99, declaredValueCents: 200000 },
              }),
            IdempotencyConflictError
          );

          // Reopen and verify idempotency persists across restart
          const reopened = ShipmentEngine.open(dir);
          const replayAfterRestart = reopened.executeCommand({
            commandId: "idem-2",
            shipmentId: "SHP-IDEM",
            type: "BOOK",
            timestamp: 5000,
            payload: { scheduledDepartureTs: 1200, vesselOrFlight: "CX870", carrierId: "CX" },
          });
          assert.equal(replayAfterRestart.deduplicated, true);
          assert.equal(replayAfterRestart.lsn, 2n);
          assert.equal(replayAfterRestart.shipment.state, "BOOKED");
        });
      },
    },
    {
      name: "suite_06_snapshot_compaction",
      weight: 0.15,
      fn: () => {
        withTempDir((dir) => {
          const engine = ShipmentEngine.open(dir);
          for (let i = 1; i <= 10; i++) {
            const sid = `SHP-C${String(i).padStart(2, "0")}`;
            engine.executeCommand({
              commandId: `create-${i}`,
              shipmentId: sid,
              type: "CREATE",
              timestamp: 1000 + i * 10,
              payload: { origin: "SHA", destination: "HAM", weightKg: 100 + i, declaredValueCents: 50000 * i },
            });
            engine.executeCommand({
              commandId: `book-${i}`,
              shipmentId: sid,
              type: "BOOK",
              timestamp: 1005 + i * 10,
              payload: { carrierId: "COSCO", vesselOrFlight: `V-${i}`, scheduledDepartureTs: 2000 + i * 10 },
            });
          }
          assert.equal(engine.getCurrentLsn(), 20n);

          // Full compact()
          engine.compact();
          const snapPath = path.join(dir, "snapshot.bin");
          const walPath = path.join(dir, "wal.bin");
          assert.ok(fs.existsSync(snapPath), "snapshot.bin must exist after compact()");
          assert.equal(fs.statSync(walPath).size, 8, "wal.bin must be 8 bytes after full compact()");

          // White-box verify snapshot.bin header & CRC32
          const snapBuf = fs.readFileSync(snapPath);
          assert.equal(snapBuf.subarray(0, 8).toString("binary"), "SHPWSNP\x01");
          assert.equal(snapBuf.readBigUInt64BE(8), 20n);
          const snapPayloadLen = snapBuf.readUInt32BE(16);
          const snapCrc = snapBuf.readUInt32BE(20);
          assert.equal(snapBuf.length, 24 + snapPayloadLen);
          const expectedSnapCrc = refCrc32(
            Buffer.concat([snapBuf.subarray(0, 20), snapBuf.subarray(24, 24 + snapPayloadLen)])
          );
          assert.equal(snapCrc, expectedSnapCrc);

          // Append 5 more commands (LSN 21..25)
          for (let i = 1; i <= 5; i++) {
            const sid = `SHP-C${String(i).padStart(2, "0")}`;
            engine.executeCommand({
              commandId: `dispatch-${i}`,
              shipmentId: sid,
              type: "DISPATCH",
              timestamp: 3000 + i * 10,
              payload: { departedAtTs: 2500 + i * 10, originPort: "SHA-PORT" },
            });
          }
          assert.equal(engine.getCurrentLsn(), 25n);

          // Save raw wal.bin (with LSN 21..25) before compactUpTo(23n) to test mid-compaction crash recovery
          const walBeforePartialCompact = fs.readFileSync(walPath);

          // Partial compactUpTo(23n)
          engine.compactUpTo(23n);
          const snapBuf2 = fs.readFileSync(snapPath);
          assert.equal(snapBuf2.readBigUInt64BE(8), 23n);

          // Reopen after partial compaction + leftover .tmp files
          fs.writeFileSync(path.join(dir, "snapshot.bin.tmp"), "partial-temp-junk");
          const reopened = ShipmentEngine.open(dir);
          assert.ok(!fs.existsSync(path.join(dir, "snapshot.bin.tmp")), "Must clean up .tmp files on open");
          assert.equal(reopened.getCurrentLsn(), 25n);
          assert.equal(reopened.getRecoveryStats().snapshotLoaded, true);
          assert.equal(reopened.getRecoveryStats().snapshotLastLsn, 23n);
          assert.equal(reopened.getRecoveryStats().replayedFrames, 2);

          // Simulate crash after snapshot.bin updated to 23n but before wal.bin (21..25) was replaced
          fs.writeFileSync(walPath, walBeforePartialCompact);
          const recoveredMidCompact = ShipmentEngine.open(dir);
          assert.equal(recoveredMidCompact.getCurrentLsn(), 25n);
          assert.equal(recoveredMidCompact.getShipment("SHP-C05").state, "IN_TRANSIT");

          // Verify corrupted snapshot throws SnapshotCorruptionError
          const badSnap = Buffer.from(fs.readFileSync(snapPath));
          badSnap[badSnap.length - 2] ^= 0xff;
          fs.writeFileSync(snapPath, badSnap);
          assert.throws(() => ShipmentEngine.open(dir), SnapshotCorruptionError);
        });
      },
    },
  ];

  const results = {};
  let totalScore = 0;
  let allCorePassed = true;

  for (const s of suites) {
    try {
      s.fn();
      results[s.name] = { status: "PASS", score: s.weight };
      totalScore += s.weight;
      console.log(`[verifier] PASS ${s.name} (+${s.weight.toFixed(2)})`);
    } catch (err) {
      allCorePassed = false;
      results[s.name] = { status: "FAIL", score: 0, error: String(err?.stack || err) };
      console.error(`[verifier] FAIL ${s.name}: ${err?.message || err}`);
    }
  }

  // Suite 7: Stress & Crash-Consistency Under Load (0.10), gated on Suites 1-6 passing
  const perfWeight = 0.10;
  if (!allCorePassed) {
    results["suite_07_stress_consistency"] = {
      status: "SKIP",
      score: 0,
      reason: "Gated on passing suites 1-6",
    };
    console.log("[verifier] SKIP suite_07_stress_consistency (core suites failed)");
  } else {
    try {
      withTempDir((dir) => {
        let engine = ShipmentEngine.open(dir);
        const totalShipments = 200;
        let cmdSeq = 0;

        for (let i = 1; i <= totalShipments; i++) {
          const sid = `SHP-STRESS-${String(i).padStart(4, "0")}`;
          const createCmd = {
            commandId: `cmd-${++cmdSeq}`,
            shipmentId: sid,
            type: "CREATE",
            timestamp: 1000 + i,
            payload: { origin: "ADD", destination: "LHR", weightKg: 10 + i, declaredValueCents: 10000 * i },
          };
          engine.executeCommand(createCmd);

          // Interleaved idempotent retry every 10th shipment
          if (i % 10 === 0) {
            const retryRes = engine.executeCommand(createCmd);
            assert.equal(retryRes.deduplicated, true);
          }

          engine.executeCommand({
            commandId: `cmd-${++cmdSeq}`,
            shipmentId: sid,
            type: "BOOK",
            timestamp: 2000 + i,
            payload: { carrierId: "ET", vesselOrFlight: `ET-${i}`, scheduledDepartureTs: 3000 + i },
          });
          engine.executeCommand({
            commandId: `cmd-${++cmdSeq}`,
            shipmentId: sid,
            type: "DISPATCH",
            timestamp: 4000 + i,
            payload: { departedAtTs: 3500 + i, originPort: "ADD-CARGO" },
          });
          if (i % 2 === 0) {
            engine.executeCommand({
              commandId: `cmd-${++cmdSeq}`,
              shipmentId: sid,
              type: "DELIVER",
              timestamp: 5000 + i,
              payload: { deliveredAtTs: 4500 + i, receiverSignature: `SIG-${i}` },
            });
          } else {
            engine.executeCommand({
              commandId: `cmd-${++cmdSeq}`,
              shipmentId: sid,
              type: "HOLD",
              timestamp: 5000 + i,
              payload: { reasonCode: "TEMP_CHECK", heldAtTs: 4600 + i },
            });
            engine.executeCommand({
              commandId: `cmd-${++cmdSeq}`,
              shipmentId: sid,
              type: "RESUME",
              timestamp: 6000 + i,
              payload: { resumedAtTs: 5500 + i, clearanceRef: `REF-${i}` },
            });
            engine.executeCommand({
              commandId: `cmd-${++cmdSeq}`,
              shipmentId: sid,
              type: "DELIVER",
              timestamp: 7000 + i,
              payload: { deliveredAtTs: 6500 + i, receiverSignature: `SIG-${i}` },
            });
          }

          if (i % 50 === 0) {
            engine.compactUpTo(engine.getCurrentLsn() - 10n);
            // Simulate torn tail + reopen
            fs.appendFileSync(path.join(dir, "wal.bin"), Buffer.from([0x53, 0x48, 0x50]));
            engine = ShipmentEngine.open(dir);
            assert.equal(engine.getRecoveryStats().recoveredTornBytes, 3);
          }
        }

        const all = engine.listShipments();
        assert.equal(all.length, totalShipments);
        assert.ok(all.every((s) => s.state === "DELIVERED"));
        assert.equal(engine.getCurrentLsn(), 1000n);

        results["suite_07_stress_consistency"] = {
          status: "PASS",
          score: perfWeight,
        };
        totalScore += perfWeight;
        console.log(`[verifier] PASS suite_07_stress_consistency (+${perfWeight.toFixed(2)})`);
      });
    } catch (err) {
      results["suite_07_stress_consistency"] = {
        status: "FAIL",
        score: 0,
        error: String(err?.stack || err),
      };
      console.error(`[verifier] FAIL suite_07_stress_consistency: ${err?.message || err}`);
    }
  }

  writeReward(totalScore, { suites: results });
}

main().catch((err) => {
  writeReward(0, { error: String(err?.stack || err) });
});

