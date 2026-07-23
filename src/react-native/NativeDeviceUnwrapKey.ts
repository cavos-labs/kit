import { p256 } from "@noble/curves/p256";
import type { DeviceUnwrapKey } from "../chains/stellar/DeviceUnwrapKey";
import { deviceSlotId } from "../chains/stellar/DeviceUnwrapKey";
import { eciesKEKFromX, unwrapDEK } from "../chains/stellar/envelope";
import { assertSecurity, type MinimumKeySecurity } from "./NativeDeviceSigner";
import { fromBase64, toBase64 } from "./encoding";
import { nativeModule, type NativeSecurityLevel } from "./NativeModule";

export interface NativeDeviceUnwrapKeyOptions {
  keyId: string;
  minimumKeySecurity?: MinimumKeySecurity;
}

export class NativeDeviceUnwrapKey implements DeviceUnwrapKey {
  private constructor(
    readonly keyId: string,
    readonly securityLevel: NativeSecurityLevel,
    private readonly publicKey: Uint8Array,
  ) {}

  static async loadOrCreate(opts: NativeDeviceUnwrapKeyOptions): Promise<NativeDeviceUnwrapKey> {
    const result = await nativeModule().getOrCreateUnwrapKey(opts.keyId);
    assertSecurity(result.securityLevel, opts.minimumKeySecurity ?? "os-protected");
    const publicKey = fromBase64(result.publicKey);
    if (publicKey.length !== 65 || publicKey[0] !== 4) throw new Error("kit/native: invalid ECDH public key");
    return new NativeDeviceUnwrapKey(opts.keyId, result.securityLevel, publicKey);
  }

  publicKeySec1(): Uint8Array {
    return this.publicKey.slice();
  }

  slotId(): string {
    return deviceSlotId(this.publicKey);
  }

  async unwrap(blob: Uint8Array): Promise<Uint8Array> {
    const ephemeral = blob.subarray(0, 33);
    const uncompressed = p256.ProjectivePoint.fromHex(ephemeral).toRawBytes(false);
    const sharedX = fromBase64(
      await nativeModule().deriveSharedSecret(this.keyId, toBase64(uncompressed)),
    );
    return unwrapDEK(blob.subarray(33), eciesKEKFromX(sharedX, ephemeral));
  }
}
