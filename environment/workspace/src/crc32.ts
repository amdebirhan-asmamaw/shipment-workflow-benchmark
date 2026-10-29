import { CommandType } from "./types.js";

/**
 * Deterministic canonical JSON serializer:
 * - Recursively sorts object keys in ascending UTF-16 code-unit order.
 * - Omits object keys whose value is undefined.
 * - Preserves array order.
 */
export function canonicalJson(_value: unknown): string {
  throw new Error("canonicalJson is not implemented");
}

/**
 * Standard IEEE 802.3 CRC32 (reflected polynomial 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF).
 * Returns an unsigned 32-bit integer (>>> 0).
 */
export function crc32(_data: Uint8Array): number {
  throw new Error("crc32 is not implemented");
}

/**
 * Computes the 64-character lowercase hex SHA-256 digest of
 * canonicalJson({ payload, shipmentId, type }).
 */
export function computeCommandHash(
  _shipmentId: string,
  _type: CommandType,
  _payload: unknown
): string {
  throw new Error("computeCommandHash is not implemented");
}

