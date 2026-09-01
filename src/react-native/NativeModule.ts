import { requireNativeModule } from "expo-modules-core";

export type NativeSecurityLevel =
  | "secure-enclave"
  | "strongbox"
  | "tee"
  | "os-protected"
  | "development";

export interface NativeCapabilities {
  signingKey: NativeSecurityLevel;
  ecdhKey: NativeSecurityLevel;
  passkey: boolean;
  passkeyPrf: boolean;
}

export interface NativeKeyResult {
  publicKey: string;
  securityLevel: NativeSecurityLevel;
}

export interface NativePasskeyRegistration {
  credentialId: string;
  publicKey: string;
  prfSecret?: string;
}

export interface NativePasskeyAssertionResult {
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  prfSecret?: string;
}

/** Result of native ed25519 signing — only signature + public key, never seed. */
export interface NativeControlSignResult {
  signature: string;
  publicKey: string;
}

/** Result of native control public key derivation. */
export interface NativeControlPublicKeyResult {
  publicKey: string;
}

export interface CavosKitNativeModule {
  getOrCreateSigningKey(alias: string): Promise<NativeKeyResult>;
  sign(alias: string, payload: string): Promise<string>;
  getOrCreateUnwrapKey(alias: string): Promise<NativeKeyResult>;
  deriveSharedSecret(alias: string, peerPublicKey: string): Promise<string>;
  deleteKeys(alias: string): Promise<void>;
  getCapabilities(): Promise<NativeCapabilities>;
  randomBytes(length: number): Promise<string>;
  getStoredValue(key: string): Promise<string | null>;
  setStoredValue(key: string, value: string | null): Promise<void>;
  createPasskey(optionsJson: string): Promise<NativePasskeyRegistration>;
  getPasskey(optionsJson: string): Promise<NativePasskeyAssertionResult>;

  /**
   * Native ed25519 signing — the control seed never crosses the JS bridge.
   *
   * Performs ECDH → KEK derivation → DEK unwrap → control seed open → ed25519 sign
   * entirely in native code. The seed is wiped after signing.
   *
   * @param alias - Device key alias (same as getOrCreateUnwrapKey)
   * @param deviceWrap - Base64 ECIES wrap: ephPubCompressed(33) || nonce(12) || ct
   * @param ciphertext - Base64 control ciphertext: nonce(12) || AES-GCM(dek, seed)
   * @param data - Base64 data to sign
   * @returns { signature: base64, publicKey: base64 }
   */
  unwrapControlAndSign(
    alias: string,
    deviceWrap: string,
    ciphertext: string,
    data: string,
  ): Promise<NativeControlSignResult>;

  /**
   * Get the ed25519 public key for a control seed without exposing it to JS.
   *
   * @param alias - Device key alias
   * @param deviceWrap - Base64 ECIES wrap
   * @param ciphertext - Base64 control ciphertext
   * @returns { publicKey: base64 }
   */
  unwrapControlPublicKey(
    alias: string,
    deviceWrap: string,
    ciphertext: string,
  ): Promise<NativeControlPublicKeyResult>;
}

let cached: CavosKitNativeModule | undefined;

export function nativeModule(): CavosKitNativeModule {
  cached ??= requireNativeModule<CavosKitNativeModule>("CavosKit");
  return cached!;
}
