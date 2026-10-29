import { SnapshotData } from "./types.js";

export class SnapshotStore {
  public readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  /**
   * Loads and validates snapshot.bin if it exists on disk.
   * Returns null if snapshot.bin does not exist.
   * Throws SnapshotCorruptionError if the file header, length, CRC32, or JSON payload is invalid.
   */
  public load(): SnapshotData | null {
    throw new Error("SnapshotStore.load is not implemented");
  }

  /**
   * Atomically writes snapshot.bin via snapshot.bin.tmp + fsync + rename.
   */
  public saveAtomic(_data: SnapshotData): void {
    throw new Error("SnapshotStore.saveAtomic is not implemented");
  }
}

