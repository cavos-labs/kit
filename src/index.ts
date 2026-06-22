/**
 * @cavos/kit — device-native verifiable smart accounts.
 *
 * Phase 1: Starknet silent device signers (secp256r1). The device key lives on
 * the device (non-extractable WebCrypto key on web, Secure Enclave on native)
 * and signs invisibly — no passkey, no biometrics. OAuth / email only derive the
 * account address. The API is chain-configurable so Stellar and Solana adapters
 * slot in later behind the same `ChainAdapter` interface.
 */

// High-level entry point (Privy-like: log in -> ready, deployed, gasless wallet)
export { Cavos } from "./Cavos";
export type { ConnectOptions, ConnectStatus, RecoveryOptions } from "./Cavos";

// Auth / identity
export type { AuthProvider, Identity } from "./auth/AuthProvider";
export { StaticIdentity } from "./auth/AuthProvider";
export { CavosAuth } from "./auth/CavosAuth";
export type { CavosAuthOptions } from "./auth/CavosAuth";

// Identity derivation
export { deriveAddressSeed } from "./identity";
export type { IdentityInput } from "./identity";

// Off-chain user_id -> wallet map (multi-device recognition; backend-implemented)
export type { WalletRegistry, RegisteredWallet } from "./registry/WalletRegistry";
export { InMemoryWalletRegistry } from "./registry/WalletRegistry";
export { HttpWalletRegistry } from "./registry/HttpWalletRegistry";
export type { HttpWalletRegistryOptions } from "./registry/HttpWalletRegistry";

// Multi-device recovery relay (device-approval request → on-chain add_signer)
export type { RecoveryClient, PendingDeviceRequest } from "./recovery/RecoveryClient";
export { HttpRecoveryClient } from "./recovery/HttpRecoveryClient";
export type { HttpRecoveryClientOptions } from "./recovery/HttpRecoveryClient";

// Self-custodial recovery: derive a backup signer from a code (cross-chain,
// off-chain derivation; registered on-chain as an ordinary signer).
export { BackupSigner, generateRecoveryCode, deriveBackupKey } from "./recovery/BackupSigner";

// Signers
export type { DeviceSigner, DevicePublicKey, DeviceSignature } from "./signer/DeviceSigner";
export { WebCryptoSigner } from "./signer/WebCryptoSigner";
export type { WebCryptoSignerOptions } from "./signer/WebCryptoSigner";

// Chain adapters
export type { ChainAdapter, ChainCall, ComputeAddressParams } from "./chains/ChainAdapter";
export { StarknetAdapter } from "./chains/starknet/StarknetAdapter";
export type { StarknetAdapterOptions } from "./chains/starknet/StarknetAdapter";
export { StarknetDeviceSigner } from "./chains/starknet/StarknetDeviceSigner";
export {
  STARKNET_NETWORKS,
  UDC_ADDRESS,
  DEVICE_ACCOUNT_CLASS_HASH,
} from "./chains/starknet/constants";
export type { StarknetNetwork } from "./chains/starknet/constants";

// Low-level crypto / encoding (advanced use)
export { signatureToFelts, recoverYParity } from "./crypto/signature";
export {
  u256ToFelts,
  bytesToBigInt,
  bytesToHex,
  hexToBytes,
  bigIntTo32Bytes,
} from "./crypto/encoding";
