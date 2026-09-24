import { gcm } from "@noble/ciphers/aes";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { utf8ToBytes } from "../crypto/encoding";
import { parseMasterDEK, zeroize, type MasterDEK } from "./dek";

/**
 * A MasterDEK encrypted under a key only the passkey can produce: the PRF
 * output, stretched by HKDF. Cavos stores it and cannot open it.
 *
 * Layout: version(1) || nonce(12) || AES-GCM(kek, dek)(32 + 16).
 */
export type PasskeyWrap = Uint8Array & { readonly __brand: "PasskeyWrap" };

const VERSION = 0x01;
const NONCE_LEN = 12;
const WRAP_LEN = 1 + NONCE_LEN + 32 + 16;
const INFO = "cavos-passkey-dek-wrap-v1";

/** Whose DEK this is. Bound into the ciphertext, so a wrap moved to another user or app does not open. */
export interface WrapOwner {
  appId: string;
  userId: string;
}

export function wrapDek(dek: MasterDEK, prf: Uint8Array, owner: WrapOwner): PasskeyWrap {
  const kek = deriveKek(prf);
  try {
    const nonce = randomBytes(NONCE_LEN);
    const sealed = gcm(kek, nonce, aad(owner)).encrypt(dek);
    const wrap = new Uint8Array(WRAP_LEN);
    wrap[0] = VERSION;
    wrap.set(nonce, 1);
    wrap.set(sealed, 1 + NONCE_LEN);
    return wrap as PasskeyWrap;
  } finally {
    zeroize(kek);
  }
}

/** Throws when the wrap is malformed, from another owner, or sealed under another passkey. */
export function unwrapDek(wrap: Uint8Array, prf: Uint8Array, owner: WrapOwner): MasterDEK {
  if (wrap.length !== WRAP_LEN || wrap[0] !== VERSION) {
    throw new Error("kit/secret: unknown passkey wrap format");
  }
  const kek = deriveKek(prf);
  try {
    const nonce = wrap.subarray(1, 1 + NONCE_LEN);
    return parseMasterDEK(gcm(kek, nonce, aad(owner)).decrypt(wrap.subarray(1 + NONCE_LEN)));
  } finally {
    zeroize(kek);
  }
}

function deriveKek(prf: Uint8Array): Uint8Array {
  if (prf.length < 32) throw new Error("kit/secret: passkey PRF output too short");
  return hkdf(sha256, prf, undefined, INFO, 32);
}

function aad({ appId, userId }: WrapOwner): Uint8Array {
  return utf8ToBytes(`${appId}:${userId}`);
}
