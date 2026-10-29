import {
  CommandExecutionResult,
  RecoveryStats,
  ShipmentCommand,
  ShipmentRecord,
} from "./types.js";

export class ShipmentEngine {
  public readonly dataDir: string;

  private constructor(dataDir: string) {
    this.dataDir = dataDir;
  }

  /**
   * Opens the engine at dataDir, cleans up any leftover .tmp files from interrupted
   * compactions, loads snapshot.bin (if present), recovers and replays wal.bin,
   * and returns the initialized ShipmentEngine instance.
   */
  public static open(_dataDir: string): ShipmentEngine {
    throw new Error("ShipmentEngine.open is not implemented");
  }

  /**
   * Returns recovery statistics from the most recent open() call.
   */
  public getRecoveryStats(): RecoveryStats {
    throw new Error("ShipmentEngine.getRecoveryStats is not implemented");
  }

  /**
   * Returns the current highest committed LSN (0n if no commands have been committed).
   */
  public getCurrentLsn(): bigint {
    throw new Error("ShipmentEngine.getCurrentLsn is not implemented");
  }

  /**
   * Executes a shipment workflow command with SHA-256 idempotency, state transition
   * validation, and synchronous WAL persistence.
   */
  public executeCommand(_cmd: ShipmentCommand): CommandExecutionResult {
    throw new Error("ShipmentEngine.executeCommand is not implemented");
  }

  /**
   * Returns a deep clone of the shipment state for shipmentId, or null if not found.
   */
  public getShipment(_shipmentId: string): ShipmentRecord | null {
    throw new Error("ShipmentEngine.getShipment is not implemented");
  }

  /**
   * Returns all shipments sorted by shipmentId in ascending lexicographical order.
   */
  public listShipments(): ShipmentRecord[] {
    throw new Error("ShipmentEngine.listShipments is not implemented");
  }

  /**
   * Compacts all state up to currentLsn into snapshot.bin and truncates wal.bin
   * to retain only the 8-byte WAL header.
   */
  public compact(): void {
    throw new Error("ShipmentEngine.compact is not implemented");
  }

  /**
   * Compacts committed state up to targetLsn (0n <= targetLsn <= currentLsn) into
   * snapshot.bin and rewrites wal.bin to retain only frames with lsn > targetLsn.
   */
  public compactUpTo(_targetLsn: bigint): void {
    throw new Error("ShipmentEngine.compactUpTo is not implemented");
  }
}

