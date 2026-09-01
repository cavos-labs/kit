import { StrKey } from "@stellar/stellar-sdk";
import type { ControlKey } from "../chains/stellar/WebCryptoControlKey";
import { nativeModule } from "./NativeModule";
import { fromBase64, toBase64 } from "./encoding";

/**
 * TODO(android): Implement Kotlin equivalent of iOS unwrapControlAndSign.
 *
 * The iOS implementation (CavosKitModule.swift) uses:
 * - Security framework for P-256 ECDH (SE-backed when available)
 * - CryptoKit for HKDF-SHA256, AES-GCM, Curve25519.Signing
 *
 * For Android, the equivalent would use:
 * - AndroidKeyStore for P-256 ECDH (StrongBox when available)
 * - javax.crypto / BouncyCastle for HKDF, AES-GCM
 * - A pure-Java/Kotlin ed25519 implementation (e.g. TweetNaCl or custom)
 *
 * Until then, NativeControlSigner will throw on Android. The web/JS path
 * (WebCryptoControlKey) works fine on Android React Native since Unit 1
 * ensures the seed is never on the instance.
 */

/**
 * Native ed25519 control key signer for React Native.
 *
 * This implementation keeps the control seed entirely within the native process.
 * Unlike WebCryptoControlKey which imports the seed into WebCrypto (non-extractable),
 * NativeControlSigner never materializes the seed in JavaScript at all — only
 * signatures and the public key cross the JS bridge.
 *
 * **Security model**:
 * - The device's P-256 ECDH key (SE-backed when available) protects the DEK
 * - The DEK unwraps the control seed from the on-chain envelope (cv:ct)
 * - Ed25519 signing happens in native code, using CryptoKit's Curve25519
 * - The native function wipes the seed from memory after signing
 * - No biometric / Face ID prompt — access is AfterFirstUnlockThisDeviceOnly
 *
 * **Usage**:
 * ```ts
 * const signer = await NativeControlSigner.create({
 *   keyId: address,
 *   deviceWrap: env.deviceWraps[deviceKey.slotId()],
 *   ciphertext: env.ct,
 * });
 * const sig = await signer.sign(txHash);
 * ```
 */
export class NativeControlSigner implements ControlKey {
  private constructor(
    readonly keyId: string,
    private readonly deviceWrapBase64: string,
    private readonly ciphertextBase64: string,
    private readonly publicKeyRawBytes: Uint8Array,
  ) {}

  /**
   * Create a native control signer from the on-chain envelope data.
   *
   * NOTE: Currently iOS only. Android support requires a Kotlin implementation
   * of unwrapControlAndSign — see TODO at top of this file.
   *
   * @param opts.keyId - The device key alias (same as used in NativeDeviceUnwrapKey)
   * @param opts.deviceWrap - This device's ECIES wrap of the DEK from the envelope
   * @param opts.ciphertext - The cv:ct ciphertext containing the encrypted control seed
   */
  static async create(opts: {
    keyId: string;
    deviceWrap: Uint8Array;
    ciphertext: Uint8Array;
  }): Promise<NativeControlSigner> {
    // Check if native signing is available
    const module = nativeModule();
    if (typeof module.unwrapControlPublicKey !== "function") {
      throw new Error(
        "kit/native: NativeControlSigner is iOS-only. Use WebCryptoControlKey on Android.",
      );
    }

    const deviceWrapBase64 = toBase64(opts.deviceWrap);
    const ciphertextBase64 = toBase64(opts.ciphertext);

    // Get the public key (native unwraps, derives pubkey, wipes seed)
    const result = await nativeModule().unwrapControlPublicKey(
      opts.keyId,
      deviceWrapBase64,
      ciphertextBase64,
    );

    const publicKeyRaw = fromBase64(result.publicKey);
    if (publicKeyRaw.length !== 32) {
      throw new Error("kit/native: invalid ed25519 public key length");
    }

    return new NativeControlSigner(
      opts.keyId,
      deviceWrapBase64,
      ciphertextBase64,
      publicKeyRaw,
    );
  }

  publicAddress(): string {
    return StrKey.encodeEd25519PublicKey(Buffer.from(this.publicKeyRawBytes));
  }

  publicKeyRaw(): Uint8Array {
    return this.publicKeyRawBytes;
  }

  /**
   * Sign data with the control key, entirely within the native process.
   *
   * The native function:
   * 1. Performs ECDH with the SE-protected device key
   * 2. Derives KEK and unwraps DEK
   * 3. Opens the control seed from ciphertext
   * 4. Signs with ed25519
   * 5. Wipes the seed from memory
   * 6. Returns only the signature
   *
   * @returns 64-byte Ed25519 signature
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    const result = await nativeModule().unwrapControlAndSign(
      this.keyId,
      this.deviceWrapBase64,
      this.ciphertextBase64,
      toBase64(data),
    );

    const signature = fromBase64(result.signature);
    if (signature.length !== 64) {
      throw new Error("kit/native: invalid ed25519 signature length");
    }

    return signature;
  }
}
