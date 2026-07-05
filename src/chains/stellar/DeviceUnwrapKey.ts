import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { eciesUnwrapDEK } from "./envelope";

/**
 * The device's P-256 **ECDH** key used only to unwrap the account DEK.
 *
 * Note this is a SEPARATE key from the `DeviceSigner` (which is an ECDSA signing
 * key, non-extractable, and therefore cannot do ECDH). This key is per-device
 * and non-syncable — losing the device loses only this convenience factor, not
 * the account (the passkey / recovery factors survive). Its public key goes into
 * the account's `cv:wd:<id>` on-chain envelope slot; the DEK is ECIES-wrapped to
 * it so daily unlock is silent.
 *
 * `LocalDeviceUnwrapKey` holds a raw scalar (Node / tests / React Native secure
 * storage). The browser implementation wraps a non-extractable WebCrypto ECDH
 * key and overrides `unwrap` with `deriveBits`; it never exposes the scalar.
 */
export interface DeviceUnwrapKey {
  /** SEC1 *uncompressed* (65-byte) public key — the ECIES recipient key that is
   *  published on-chain in the device's envelope slot. */
  publicKeySec1(): Uint8Array;
  /** A short, stable id for this device's envelope slot (`cv:wd:<id>`). */
  slotId(): string;
  /** Unwrap the account DEK from this device's ECIES blob. */
  unwrap(blob: Uint8Array): Promise<Uint8Array>;
}

/** Raw-scalar device unwrap key (Node / React Native). */
export class LocalDeviceUnwrapKey implements DeviceUnwrapKey {
  private constructor(private readonly scalar: Uint8Array) {}

  /** Generate a fresh device unwrap key. */
  static generate(): LocalDeviceUnwrapKey {
    return new LocalDeviceUnwrapKey(p256.utils.randomPrivateKey());
  }

  /** Rebuild from a persisted 32-byte scalar. */
  static fromScalar(scalar: Uint8Array): LocalDeviceUnwrapKey {
    if (scalar.length !== 32) throw new Error("kit/stellar: device unwrap scalar must be 32 bytes");
    return new LocalDeviceUnwrapKey(scalar);
  }

  /** The raw scalar, for the caller to persist in secure storage. */
  export(): Uint8Array {
    return this.scalar;
  }

  publicKeySec1(): Uint8Array {
    return p256.getPublicKey(this.scalar, false);
  }

  slotId(): string {
    return deviceSlotId(this.publicKeySec1());
  }

  async unwrap(blob: Uint8Array): Promise<Uint8Array> {
    return eciesUnwrapDEK(blob, this.scalar);
  }
}

/** Stable short slot id for a device's envelope entry: first 8 hex of
 *  `sha256(pubkey)`. Deterministic from the public key, so it's the same on
 *  every read and can't collide in practice for a handful of devices. */
export function deviceSlotId(publicKeySec1: Uint8Array): string {
  const h = sha256(publicKeySec1);
  let s = "";
  for (const b of h.subarray(0, 4)) s += b.toString(16).padStart(2, "0");
  return s;
}

/** For tests: a random slot id (when no key is involved). */
export function randomSlotId(): string {
  let s = "";
  for (const b of randomBytes(4)) s += b.toString(16).padStart(2, "0");
  return s;
}
