export type ShipmentState =
  | "CREATED"
  | "BOOKED"
  | "IN_TRANSIT"
  | "HELD"
  | "DELIVERED"
  | "CANCELLED";

export type CommandType =
  | "CREATE"
  | "BOOK"
  | "DISPATCH"
  | "HOLD"
  | "RESUME"
  | "DELIVER"
  | "CANCEL";

export const WAL_FILE_HEADER = Buffer.from("SHPWWAL\x01", "binary");
export const WAL_FRAME_MAGIC = 0x53485057; // "SHPW"
export const WAL_FRAME_VERSION = 1;
export const WAL_FRAME_HEADER_BYTES = 24;
export const WAL_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;

export const SNAPSHOT_FILE_HEADER = Buffer.from("SHPWSNP\x01", "binary");
export const SNAPSHOT_HEADER_BYTES = 24;

export enum WalRecordType {
  COMMAND_COMMIT = 1,
  CHECKPOINT_MARKER = 2,
}

export interface ShipmentCommand {
  commandId: string;
  shipmentId: string;
  type: CommandType;
  timestamp: number;
  payload: Record<string, unknown>;
}

export interface ShipmentRecord {
  shipmentId: string;
  state: ShipmentState;
  version: number;
  origin: string;
  destination: string;
  weightKg: number;
  declaredValueCents: number;
  createdAtTs: number;
  updatedAtTs: number;
  lastCommandId: string;
  lastLsn: string;
  carrierId: string | null;
  vesselOrFlight: string | null;
  scheduledDepartureTs: number | null;
  departedAtTs: number | null;
  originPort: string | null;
  heldFromState: "BOOKED" | "IN_TRANSIT" | null;
  holdReason: string | null;
  heldAtTs: number | null;
  resumedAtTs: number | null;
  clearanceRef: string | null;
  deliveredAtTs: number | null;
  receiverSignature: string | null;
  cancelledAtTs: number | null;
  cancelReason: string | null;
}

export interface WalCommitPayload {
  command: ShipmentCommand;
  commandHash: string;
  lsn: string;
  shipment: ShipmentRecord;
}

export interface WalFrame {
  recordType: WalRecordType;
  flags: number;
  lsn: bigint;
  payload: WalCommitPayload | Record<string, unknown>;
  frameOffset: number;
  frameByteLength: number;
  crc32: number;
}

export interface RecoveryStats {
  replayedFrames: number;
  recoveredTornBytes: number;
  snapshotLoaded: boolean;
  snapshotLastLsn: bigint;
  currentLsn: bigint;
}

export interface IdempotencyEntry {
  commandId: string;
  commandHash: string;
  lsn: string;
  resultSnapshot: ShipmentRecord;
}

export interface SnapshotData {
  lastLsn: string;
  shipments: Record<string, ShipmentRecord>;
  idempotencyIndex: Record<string, IdempotencyEntry>;
}

export interface CommandExecutionResult {
  lsn: bigint;
  shipment: ShipmentRecord;
  deduplicated: boolean;
}

export class WalCorruptionError extends Error {
  public readonly offset: number;
  public readonly lsn: bigint;

  constructor(message: string, offset: number, lsn: bigint = 0n) {
    super(message);
    this.name = "WalCorruptionError";
    this.offset = offset;
    this.lsn = lsn;
  }
}

export class SnapshotCorruptionError extends Error {
  public readonly offset: number;

  constructor(message: string, offset: number = 0) {
    super(message);
    this.name = "SnapshotCorruptionError";
    this.offset = offset;
  }
}

export class IdempotencyConflictError extends Error {
  public readonly commandId: string;

  constructor(message: string, commandId: string) {
    super(message);
    this.name = "IdempotencyConflictError";
    this.commandId = commandId;
  }
}

export class InvalidTransitionError extends Error {
  public readonly shipmentId: string;
  public readonly currentState: ShipmentState | null;
  public readonly commandType: CommandType;

  constructor(
    message: string,
    shipmentId: string,
    currentState: ShipmentState | null,
    commandType: CommandType
  ) {
    super(message);
    this.name = "InvalidTransitionError";
    this.shipmentId = shipmentId;
    this.currentState = currentState;
    this.commandType = commandType;
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

