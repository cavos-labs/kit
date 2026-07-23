import { sha256 } from "@noble/hashes/sha256";
import type { DevicePublicKey, DeviceSignature, DeviceSigner } from "../signer/DeviceSigner";
import { bytesToBigInt } from "../crypto/encoding";
import { derToRs } from "../crypto/webauthn";
import { recoverYParity } from "../crypto/signature";
import { fromBase64, toBase64 } from "./encoding";
import { nativeModule, type NativeSecurityLevel } from "./NativeModule";

export type MinimumKeySecurity = "os-protected" | "hardware";

export interface NativeDeviceSignerOptions {
  keyId: string;
  minimumKeySecurity?: MinimumKeySecurity;
}

export class NativeDeviceSigner implements DeviceSigner {
  private constructor(
    readonly keyId: string,
    readonly securityLevel: NativeSecurityLevel,
    private readonly publicKey: DevicePublicKey,
  ) {}

  static async loadOrCreate(opts: NativeDeviceSignerOptions): Promise<NativeDeviceSigner> {
    const result = await nativeModule().getOrCreateSigningKey(opts.keyId);
    assertSecurity(result.securityLevel, opts.minimumKeySecurity ?? "os-protected");
    const raw = fromBase64(result.publicKey);
    if (raw.length !== 65 || raw[0] !== 4) throw new Error("kit/native: invalid P-256 public key");
    return new NativeDeviceSigner(opts.keyId, result.securityLevel, {
      x: bytesToBigInt(raw.subarray(1, 33)),
      y: bytesToBigInt(raw.subarray(33, 65)),
    });
  }

  async getPublicKey(): Promise<DevicePublicKey> {
    return this.publicKey;
  }

  async sign(txHash: Uint8Array): Promise<DeviceSignature> {
    const der = fromBase64(await nativeModule().sign(this.keyId, toBase64(txHash)));
    const { r, s } = derToRs(der);
    return { r, s, yParity: recoverYParity(r, s, sha256(txHash), this.publicKey) };
  }
}

export function assertSecurity(level: NativeSecurityLevel, minimum: MinimumKeySecurity): void {
  if (minimum === "hardware" && !["secure-enclave", "strongbox", "tee"].includes(level)) {
    throw new Error(`kit/native: hardware-backed key required; device provided ${level}`);
  }
}
