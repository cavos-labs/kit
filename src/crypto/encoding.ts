/**
 * Low-level encoding helpers shared across the kit.
 */

const U128_MASK = (1n << 128n) - 1n;

/** Split a u256 into the `[low, high]` felt pair Cairo expects. */
export function u256ToFelts(value: bigint): [bigint, bigint] {
  return [value & U128_MASK, value >> 128n];
}

/** Big-endian bytes -> bigint. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "0x";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = clean.length % 2 ? "0" + clean : clean;
  const out = new Uint8Array(padded.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Serialize raw bytes into the calldata a Cairo `ByteArray` deserializes from:
 *   [ num_full_words, ...full_words(31 bytes each), pending_word, pending_len ]
 * Each full word is 31 big-endian bytes; the pending word holds the trailing
 * `< 31` bytes. Used to pass `authenticator_data` / `client_data_json` to the
 * passkey-approval entrypoint.
 */
export function bytesToByteArrayCalldata(bytes: Uint8Array): string[] {
  const CHUNK = 31;
  const fullCount = Math.floor(bytes.length / CHUNK);
  const out: string[] = [String(fullCount)];
  for (let i = 0; i < fullCount; i++) {
    out.push("0x" + bytesToBigInt(bytes.subarray(i * CHUNK, i * CHUNK + CHUNK)).toString(16));
  }
  const rem = bytes.subarray(fullCount * CHUNK);
  out.push("0x" + (rem.length ? bytesToBigInt(rem).toString(16) : "0"));
  out.push(String(rem.length));
  return out;
}

/** A felt/bigint -> 32-byte big-endian Uint8Array (the tx-hash width). */
export function bigIntTo32Bytes(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
