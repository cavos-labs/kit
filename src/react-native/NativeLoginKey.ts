import type { ChannelClientKey } from "../recovery/enclaveChannel";
import { fromBase64, toBase64 } from "./encoding";
import { nativeModule } from "./NativeModule";

/**
 * The login key on React Native: a platform ECDH P-256 key under the alias
 * `cavos-login:<appId>`, made by the same native call as the device unwrap key,
 * so its private half never reaches JavaScript.
 *
 * `create` deletes the alias first, so every login has a fresh key. Unlike the
 * browser there is no vault and no PKCE verifier: only Google and Apple sign in
 * here. Its `deriveSharedSecret` is the x coordinate the enclave channel needs,
 * but the channel also needs WebCrypto HKDF and AES-GCM, which React Native
 * does not provide. Enclave sign-in and enclave recovery therefore stay
 * unavailable on React Native until it does; this key only keeps the login
 * `nonce` correct for the enclave that will check it.
 */
export class NativeLoginKey implements ChannelClientKey {
  private constructor(
    private readonly alias: string,
    private readonly publicRaw: Uint8Array,
  ) {}

  static async create(appId: string): Promise<NativeLoginKey> {
    const alias = `cavos-login:${appId}`;
    await nativeModule().deleteKeys(alias);
    const { publicKey } = await nativeModule().getOrCreateUnwrapKey(alias);
    const publicRaw = fromBase64(publicKey);
    if (publicRaw.length !== 65 || publicRaw[0] !== 4) throw new Error("kit/native: invalid ECDH public key");
    return new NativeLoginKey(alias, publicRaw);
  }

  static async remove(appId: string): Promise<void> {
    await nativeModule().deleteKeys(`cavos-login:${appId}`);
  }

  publicKeyRaw(): Uint8Array {
    return this.publicRaw;
  }

  async deriveSharedSecret(peerPublicRaw: Uint8Array): Promise<Uint8Array> {
    return fromBase64(await nativeModule().deriveSharedSecret(this.alias, toBase64(peerPublicRaw)));
  }
}
