/**
 * secp256r1 signature helpers for silent device signers.
 */
import { p256 } from "@noble/curves/p256";
import type { DevicePublicKey, DeviceSignature } from "../signer/DeviceSigner";
import { u256ToFelts } from "./encoding";

/**
 * Serialize a device signature to the felt array for `tx_info.signature`:
 *   [ r_low, r_high, s_low, s_high, y_parity ]
 * exactly what DeviceAccount.__validate__ decodes.
 */
export function signatureToFelts(sig: DeviceSignature): bigint[] {
  const [rLow, rHigh] = u256ToFelts(sig.r);
  const [sLow, sHigh] = u256ToFelts(sig.s);
  return [rLow, rHigh, sLow, sHigh, sig.yParity ? 1n : 0n];
}

/**
 * Recover the parity bit of an (r, s) signature over `digest` for a known
 * pubkey. WebCrypto/Secure Enclave don't return a recovery id, so we derive it
 * by trying both candidates and matching the device's public key.
 */
export function recoverYParity(
  r: bigint,
  s: bigint,
  digest: Uint8Array,
  pubkey: DevicePublicKey,
): boolean {
  for (const bit of [0, 1] as const) {
    try {
      const candidate = new p256.Signature(r, s).addRecoveryBit(bit);
      const point = candidate.recoverPublicKey(digest).toAffine();
      if (point.x === pubkey.x && point.y === pubkey.y) {
        return bit === 1;
      }
    } catch {
      // try the other bit
    }
  }
  throw new Error("kit/signature: could not recover parity for the given pubkey");
}
