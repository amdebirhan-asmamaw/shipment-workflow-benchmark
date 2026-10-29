import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ShipmentEngine,
  crc32,
  canonicalJson,
  computeCommandHash,
} from "../dist/index.js";

function runSmokeTests() {
  console.log("[smoke] Testing CRC32 & canonicalJson...");
  const check = crc32(Buffer.from("123456789", "utf8"));
  assert.equal(check, 0xcbf43926, "CRC32 of '123456789' must equal 0xCBF43926");

  const c1 = canonicalJson({ b: 2, a: { y: 10, x: 20, z: undefined } });
  const c2 = canonicalJson({ a: { x: 20, y: 10 }, b: 2 });
  assert.equal(c1, '{"a":{"x":20,"y":10},"b":2}');
  assert.equal(c1, c2);

  const h1 = computeCommandHash("SHP-1", "CREATE", { origin: "ADD", destination: "FRA", weightKg: 100, declaredValueCents: 50000 });
  const h2 = computeCommandHash("SHP-1", "CREATE", { declaredValueCents: 50000, weightKg: 100, destination: "FRA", origin: "ADD" });
  assert.equal(h1, h2);
  assert.equal(h1.length, 64);

  console.log("[smoke] Testing ShipmentEngine basic lifecycle & WAL recovery...");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "shipment-wal-smoke-"));
  try {
    const engine = ShipmentEngine.open(tmpDir);
    assert.equal(engine.getCurrentLsn(), 0n);

    const r1 = engine.executeCommand({
      commandId: "cmd-1",
      shipmentId: "SHP-100",
      type: "CREATE",
      timestamp: 1000,
      payload: {
        origin: "ADD",
        destination: "AMS",
        weightKg: 250.5,
        declaredValueCents: 120000,
      },
    });
    assert.equal(r1.lsn, 1n);
    assert.equal(r1.deduplicated, false);
    assert.equal(r1.shipment.state, "CREATED");

    // Idempotent retry
    const r1Retry = engine.executeCommand({
      commandId: "cmd-1",
      shipmentId: "SHP-100",
      type: "CREATE",
      timestamp: 1005,
      payload: {
        declaredValueCents: 120000,
        weightKg: 250.5,
        destination: "AMS",
        origin: "ADD",
      },
    });
    assert.equal(r1Retry.lsn, 1n);
    assert.equal(r1Retry.deduplicated, true);
    assert.equal(engine.getCurrentLsn(), 1n);

    // Reopen and verify state persisted
    const reopened = ShipmentEngine.open(tmpDir);
    assert.equal(reopened.getCurrentLsn(), 1n);
    const s = reopened.getShipment("SHP-100");
    assert.ok(s);
    assert.equal(s.state, "CREATED");
    console.log("[smoke] All public smoke checks passed!");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runSmokeTests();

