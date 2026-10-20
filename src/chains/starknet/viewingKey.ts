import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { ec, num } from "starknet";
import { bytesToBigInt, utf8ToBytes } from "../../crypto/encoding";

/** The chain, account and STRK20 pool a viewing key is bound to (SNIP-44 `DerivationContext`, `key_index` 0). */
export interface ViewingKeyContext {
  chainId: string;
  accountAddress: string;
  poolAddress: string;
}

const ORDER = ec.starkCurve.CURVE.n;
const HALF_ORDER = ORDER / 2n;
const LIMIT = 2n ** 256n - (2n ** 256n % ORDER);
const DOMAIN = utf8ToBytes("STRK20_ACCOUNT_LEAF_V1");
const CONTEXT_VERSION = 1n;
const KEY_INDEX = 0n;

/**
 * STRK20 viewing key of a Stark account key, per SNIP-44 `account-leaf-v1`:
 * HMAC-SHA256 keyed by the private scalar, rejection-sampled into `[1, n/2)`.
 * The same key and context give the same viewing key on every device.
 *
 * The result is as sensitive as the private state it decrypts. It must never
 * leave the vault.
 */
export function deriveViewingKey(privateKey: string, context: ViewingKeyContext): string {
  const scalar = BigInt(privateKey);
  if (scalar < 1n || scalar >= ORDER) throw new Error("kit/starknet: the account key is not a Stark scalar");
  const key = i2osp(scalar, 32);
  const contextBytes = concat(
    i2osp(CONTEXT_VERSION, 4),
    i2osp(BigInt(context.chainId), 32),
    i2osp(BigInt(context.accountAddress), 32),
    i2osp(BigInt(context.poolAddress), 32),
    i2osp(KEY_INDEX, 16),
  );
  for (let counter = 0n; counter < 2n ** 32n; counter++) {
    const candidate = bytesToBigInt(hmac(sha256, key, concat(DOMAIN, contextBytes, i2osp(counter, 4))));
    if (candidate >= LIMIT) continue;
    const reduced = candidate % ORDER;
    if (reduced === 0n) continue;
    const folded = reduced < ORDER - reduced ? reduced : ORDER - reduced;
    if (folded < HALF_ORDER) return num.toHex(folded);
  }
  throw new Error("kit/starknet: viewing key derivation exhausted its counter");
}

/** Public viewing key, the x-coordinate a STRK20 pool stores for a registered account. */
export function viewingPublicKey(viewingKey: string): string {
  return ec.starkCurve.getStarkKey(viewingKey);
}

function i2osp(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >> BigInt(8 * length) !== 0n) {
    throw new Error(`kit/starknet: value does not fit in ${length} bytes`);
  }
  const out = new Uint8Array(length);
  let rest = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
