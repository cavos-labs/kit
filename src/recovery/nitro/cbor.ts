/**
 * The minimal CBOR (RFC 8949) subset needed to read a Nitro attestation
 * document, plus the one encoder case needed to rebuild a COSE `Sig_structure`.
 *
 * This is deliberately not a general CBOR library. Attestation documents are
 * adversarial input — a browser verifying one must reject anything it does not
 * fully understand rather than guess. So non-canonical integer widths, chunked
 * strings, and trailing bytes are all hard errors, and the decoder is small
 * enough to audit in one sitting.
 *
 * Indefinite-length maps and arrays ARE accepted, because the Nitro Security
 * Module genuinely emits them: a real attestation document's payload opens with
 * `0xBF`, an indefinite-length map. That makes the document non-canonical, so
 * nothing here may re-encode a decoded value and compare bytes. Signature
 * verification therefore runs over the original payload bytes as received —
 * never over a re-serialisation. Indefinite-length *strings* remain rejected;
 * the NSM does not emit them and chunked strings are a classic source of
 * parser-differential bugs.
 */

export type CborValue =
  | number
  | bigint
  | Uint8Array
  | string
  | CborValue[]
  | Map<CborValue, CborValue>
  | boolean
  | null;

/** A CBOR tag (major type 6) and the value it wraps. */
export interface CborTagged {
  tag: number;
  value: CborValue;
}

interface Cursor {
  readonly bytes: Uint8Array;
  offset: number;
}

/**
 * Decode exactly one CBOR item from `bytes`. Trailing bytes are rejected: an
 * attestation document that decodes but leaves data behind is malformed, and
 * silently ignoring the remainder is how parser-differential bugs start.
 */
export function decodeCbor(bytes: Uint8Array): CborValue | CborTagged {
  const cursor: Cursor = { bytes, offset: 0 };
  const value = decodeItem(cursor);
  if (cursor.offset !== bytes.length) {
    throw new Error("cbor: trailing bytes after top-level item");
  }
  return value;
}

function decodeItem(cursor: Cursor): CborValue | CborTagged {
  const initial = readUint8(cursor);
  const major = initial >> 5;
  const info = initial & 0x1f;

  if (info === 31) {
    // Only maps (5) and arrays (4) may be indefinite-length here. A bare break
    // code (major 7) outside a container, or a chunked string, is malformed.
    if (major === 5) return decodeIndefiniteMap(cursor);
    if (major === 4) return decodeIndefiniteArray(cursor);
    throw new Error(`cbor: indefinite-length major type ${major} is not supported`);
  }
  if (info > 27) throw new Error(`cbor: reserved additional information ${info}`);

  // Major type 7 encodes simple values, not a length.
  if (major === 7) {
    if (info === 20) return false;
    if (info === 21) return true;
    if (info === 22) return null;
    throw new Error(`cbor: unsupported simple value ${info}`);
  }

  const argument = readArgument(cursor, info);

  switch (major) {
    case 0:
      return toNumberIfSafe(argument);
    case 1:
      return toNumberIfSafe(-1n - argument);
    case 2:
      return readBytes(cursor, lengthOf(argument));
    case 3:
      return new TextDecoder("utf-8", { fatal: true }).decode(
        readBytes(cursor, lengthOf(argument)),
      );
    case 4: {
      const count = lengthOf(argument);
      const items: CborValue[] = [];
      for (let index = 0; index < count; index += 1) {
        items.push(decodeItem(cursor) as CborValue);
      }
      return items;
    }
    case 5: {
      const count = lengthOf(argument);
      const entries = new Map<CborValue, CborValue>();
      for (let index = 0; index < count; index += 1) {
        const key = decodeItem(cursor) as CborValue;
        const value = decodeItem(cursor) as CborValue;
        // Duplicate keys make the document's meaning ambiguous; a verifier and
        // a signer could disagree about which one counts.
        if (entries.has(key)) throw new Error("cbor: duplicate map key");
        entries.set(key, value);
      }
      return entries;
    }
    case 6:
      return { tag: lengthOf(argument), value: decodeItem(cursor) as CborValue };
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

/** The CBOR "break" code that terminates an indefinite-length container. */
const BREAK = 0xff;

function atBreak(cursor: Cursor): boolean {
  if (cursor.offset >= cursor.bytes.length) throw new Error("cbor: unterminated indefinite item");
  return cursor.bytes[cursor.offset] === BREAK;
}

function decodeIndefiniteArray(cursor: Cursor): CborValue {
  const items: CborValue[] = [];
  while (!atBreak(cursor)) items.push(decodeItem(cursor) as CborValue);
  cursor.offset += 1; // consume the break
  return items;
}

function decodeIndefiniteMap(cursor: Cursor): CborValue {
  const entries = new Map<CborValue, CborValue>();
  while (!atBreak(cursor)) {
    const key = decodeItem(cursor) as CborValue;
    if (atBreak(cursor)) throw new Error("cbor: map key without a value");
    const value = decodeItem(cursor) as CborValue;
    if (entries.has(key)) throw new Error("cbor: duplicate map key");
    entries.set(key, value);
  }
  cursor.offset += 1; // consume the break
  return entries;
}

/**
 * Read the argument that follows the initial byte. Widths are checked for
 * canonical (shortest-form) encoding: a value that fits in fewer bytes than it
 * was given is rejected, so the same document cannot be re-encoded two ways.
 */
function readArgument(cursor: Cursor, info: number): bigint {
  if (info < 24) return BigInt(info);
  if (info === 24) {
    const value = BigInt(readUint8(cursor));
    if (value < 24n) throw new Error("cbor: non-canonical 1-byte argument");
    return value;
  }
  const width = info === 25 ? 2 : info === 26 ? 4 : 8;
  const bytes = readBytes(cursor, width);
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  const minimum = width === 2 ? 0x100n : width === 4 ? 0x10000n : 0x100000000n;
  if (value < minimum) throw new Error(`cbor: non-canonical ${width}-byte argument`);
  return value;
}

function lengthOf(argument: bigint): number {
  if (argument > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("cbor: length exceeds supported range");
  }
  return Number(argument);
}

function toNumberIfSafe(value: bigint): number | bigint {
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value;
}

function readUint8(cursor: Cursor): number {
  if (cursor.offset >= cursor.bytes.length) throw new Error("cbor: unexpected end of input");
  return cursor.bytes[cursor.offset++];
}

function readBytes(cursor: Cursor, length: number): Uint8Array {
  if (cursor.offset + length > cursor.bytes.length) {
    throw new Error("cbor: unexpected end of input");
  }
  const slice = cursor.bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return slice;
}

/**
 * Encode the COSE `Sig_structure` array that ES384 signatures are computed
 * over: `["Signature1", protected, external_aad, payload]`. This is the only
 * value the kit ever encodes, so the encoder covers just text strings, byte
 * strings, and a fixed-size array.
 */
export function encodeSigStructure(
  protectedHeader: Uint8Array,
  externalAad: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  return concatBytes([
    Uint8Array.from([0x84]), // array(4)
    encodeTextString("Signature1"),
    encodeByteString(protectedHeader),
    encodeByteString(externalAad),
    encodeByteString(payload),
  ]);
}

function encodeTextString(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  return concatBytes([encodeHead(3, bytes.length), bytes]);
}

function encodeByteString(value: Uint8Array): Uint8Array {
  return concatBytes([encodeHead(2, value.length), value]);
}

function encodeHead(major: number, length: number): Uint8Array {
  const prefix = major << 5;
  if (length < 24) return Uint8Array.from([prefix | length]);
  if (length < 0x100) return Uint8Array.from([prefix | 24, length]);
  if (length < 0x10000) return Uint8Array.from([prefix | 25, length >> 8, length & 0xff]);
  return Uint8Array.from([
    prefix | 26,
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
  ]);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
