import type { Call, InvocationsSignerDetails, TypedData } from "starknet";
import type { SocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import type { DeviceSignature } from "../signer/DeviceSigner";
import type { Line } from "./policy";

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

/**
 * The Cavos window is the fallback for what a cross-site frame cannot do
 * safely: passkeys some browsers refuse there, and approvals where the browser
 * cannot tell whether the page is covering the frame.
 */
export type PopupIntent =
  | { kind: "passkey"; userId: string; userName: string; credentialId?: Uint8Array }
  | { kind: "review"; lines: Line[]; network: string; app: string };

export type PopupResult = { secret: Uint8Array; credentialId?: Uint8Array } | { approved: boolean } | { error: string };
