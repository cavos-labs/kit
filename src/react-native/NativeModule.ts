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
}

let cached: CavosKitNativeModule | undefined;

export function nativeModule(): CavosKitNativeModule {
  cached ??= requireNativeModule<CavosKitNativeModule>("CavosKit");
  return cached!;
}
