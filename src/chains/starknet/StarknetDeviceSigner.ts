import { Signer, num, type ArraySignatureType } from "starknet";
import type { DeviceSigner } from "../../signer/DeviceSigner";
import { signatureToFelts } from "../../crypto/signature";
import { bigIntTo32Bytes } from "../../crypto/encoding";

/**
 * A starknet.js `SignerInterface` backed by a device signer. Extends the base
 * `Signer` so all transaction/declare hash computation (v3) is reused; only the
 * raw hash-signing primitive is overridden to sign silently with the device key.
 *
 * Usage:
 *   const account = new Account(provider, address, new StarknetDeviceSigner(device), "1");
 *   await account.execute(calls); // DeviceAccount validates the device signature
 *
 * For gasless flows, hand this signer to your paymaster SDK (e.g. AVNU) the same
 * way you would any starknet.js signer.
 */
export class StarknetDeviceSigner extends Signer {
  constructor(private readonly device: DeviceSigner) {
    // Base `pk` is unused: device accounts have no single Stark private key.
    super("0x1");
  }

  /** Device accounts are not controlled by a single Stark pubkey. */
  override async getPubKey(): Promise<string> {
    return "0x0";
  }

  /** Sign the computed tx hash silently with the device signer. */
  protected override async signRaw(msgHash: string): Promise<ArraySignatureType> {
    const sig = await this.device.sign(bigIntTo32Bytes(BigInt(msgHash)));
    return signatureToFelts(sig).map((f) => num.toHex(f));
  }
}
