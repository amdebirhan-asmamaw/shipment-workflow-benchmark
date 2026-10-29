import { WalCommitPayload, WalFrame, WalRecordType } from "./types.js";

export interface WalRecoveryResult {
  frames: WalFrame[];
  recoveredTornBytes: number;
  lastValidLsn: bigint;
}

export class BinaryWal {
  public readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  /**
   * Opens or initializes the WAL file, validates the 8-byte header ("SHPWWAL\x01"),
   * scans all frames, truncates a recoverable torn tail if present, and throws
   * WalCorruptionError on any mid-log corruption or LSN discontinuity.
   */
  public openAndRecover(_baseLsn: bigint = 0n): WalRecoveryResult {
    throw new Error("BinaryWal.openAndRecover is not implemented");
  }

  /**
   * Encodes and appends a single frame to the WAL file and fsyncs it to disk.
   */
  public appendFrame(
    _lsn: bigint,
    _payload: WalCommitPayload | Record<string, unknown>,
    _recordType: WalRecordType = WalRecordType.COMMAND_COMMIT,
    _flags: number = 0
  ): WalFrame {
    throw new Error("BinaryWal.appendFrame is not implemented");
  }

  /**
   * Atomically rewrites the WAL file via a temporary file so that only frames
   * with lsn > cutoffLsn are retained after the 8-byte "SHPWWAL\x01" header.
   */
  public rewriteRetainingAfter(_cutoffLsn: bigint, _framesToRetain: WalFrame[]): void {
    throw new Error("BinaryWal.rewriteRetainingAfter is not implemented");
  }
}

