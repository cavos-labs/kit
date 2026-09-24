import type { Call, InvocationsSignerDetails, TypedData } from "starknet";
import type { SocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import type { DeviceSignature } from "../signer/DeviceSigner";

export const VAULT_READY = "cavos-vault:ready";
export const VAULT_HELLO = "cavos-vault:hello";
export const POPUP_READY = "cavos-vault:popup-ready";
export const POPUP_RESULT = "cavos-vault:popup-result";

export type VaultChain = "solana" | "stellar" | "starknet";
export type RecoveryMode = "enclave" | "passkey" | "none";

export interface ConnectParams {
  chain: VaultChain;
  network: string;
  environment?: "development" | "production";
  appSalt: string;
  userId: string;
  userName?: string;
  recovery: RecoveryMode;
  credential?: SocialRecoveryCredential;
  authToken?: string | null;
}

export interface ConnectResult {
  handle: string;
  /** Empty on Starknet, where the app derives the address from the public key. */
  address: string;
  /**
   * Null when this browser holds no key for the account yet. Ed25519 raw bytes
   * on Solana and Stellar; the uncompressed P-256 point on Starknet.
   */
  publicKey: Uint8Array | null;
  isNewAccount: boolean;
  /** A passkey the user added can restore this account on a new device. */
  passkey: boolean;
}

export interface VaultMethods {
  connect(params: ConnectParams): ConnectResult;
  signSolanaTransaction(params: { handle: string; message: Uint8Array }): Uint8Array;
  signStellarTransaction(params: { handle: string; xdr: string; networkPassphrase: string }): Uint8Array;
  signStellarAuthEntry(params: { handle: string; preimage: Uint8Array }): Uint8Array;
  signMessage(params: { handle: string; message: Uint8Array }): Uint8Array;
  signStarknetTypedData(params: { handle: string; typedData: TypedData; accountAddress: string }): string[];
  signStarknetInvoke(params: { handle: string; calls: Call[]; details: InvocationsSignerDetails }): string[];
  signStarknetMessage(params: { handle: string; message: Uint8Array }): DeviceSignature;
  forget(params: { userId: string; appSalt: string }): void;
  /** Create a passkey that can restore the connected account on another device. */
  enrollPasskey(params: {
    userId: string;
    appSalt: string;
    userName?: string;
    environment?: "development" | "production";
    authToken?: string | null;
  }): void;
}

export type VaultMethod = keyof VaultMethods;
export type VaultParams<M extends VaultMethod> = Parameters<VaultMethods[M]>[0];
export type VaultResult<M extends VaultMethod> = ReturnType<VaultMethods[M]>;

export type VaultRequest = { [M in VaultMethod]: { id: number; method: M; params: VaultParams<M> } }[VaultMethod];

export type VaultReply =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string };

export interface VaultEvent {
  event: "show" | "hide";
}

/** The Cavos window is the fallback for passkeys some browsers refuse inside a cross-site frame. */
export type PopupIntent = { kind: "passkey"; userId: string; userName: string; create: boolean; credentialId?: Uint8Array };

export type PopupResult = { secret: Uint8Array; credentialId?: Uint8Array } | { error: string };
