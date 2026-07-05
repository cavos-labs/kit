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
export { Cavos, approveDeviceEverywhere } from "./Cavos";
export type { PasskeyApprovable } from "./Cavos";
export type {
  ConnectOptions,
  ConnectStatus,
  RecoveryOptions,
  Chain,
  NetworkEnv,
  CavosWallet,
} from "./Cavos";

// Auth / identity
export type { AuthProvider, Identity } from "./auth/AuthProvider";
export { StaticIdentity } from "./auth/AuthProvider";
export { CavosAuth } from "./auth/CavosAuth";
export type { CavosAuthOptions } from "./auth/CavosAuth";

// Identity derivation
export { deriveAddressSeed, deriveAddressSeedSolana, deriveAddressSeedStellar } from "./identity";
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
export {
  SolanaAdapter,
  serializeInstructions,
  compressedPubkey,
  encodeLowSSignature,
  buildSecp256r1Instruction,
  anchorDiscriminator,
} from "./chains/solana/SolanaAdapter";
export type { SolanaAdapterOptions, InstructionData, InstructionAccount } from "./chains/solana/SolanaAdapter";
export {
  DEVICE_ACCOUNT_PROGRAM_ID,
  SECP256R1_PROGRAM_ID,
  SOLANA_NETWORKS,
} from "./chains/solana/constants";
export type { SolanaNetwork } from "./chains/solana/constants";
export { CavosSolana } from "./chains/solana/CavosSolana";
export type { ConnectSolanaOptions, RecoverSolanaOptions } from "./chains/solana/CavosSolana";
export { SolanaRelayer } from "./chains/solana/SolanaRelayer";
export type { SolanaRelayerOptions } from "./chains/solana/SolanaRelayer";

// Stellar — classic `G…` multisig account (self-custodial, no backend/registry).
// This is THE Stellar implementation: the Soroban `C…` device-account path was
// removed in favour of classic G accounts (partner requirement + simpler model).
export { STELLAR_NETWORKS, HORIZON_URL, XLM_DECIMALS } from "./chains/stellar/constants";
export type { StellarNetwork } from "./chains/stellar/constants";
export { CavosStellar } from "./chains/stellar/CavosStellar";
export type {
  ConnectStellarOptions,
  StellarConnectStatus,
} from "./chains/stellar/CavosStellar";
export { StellarAdapter } from "./chains/stellar/StellarAdapter";
export type { StellarAdapterOptions } from "./chains/stellar/StellarAdapter";
export { StellarRelayer } from "./chains/stellar/StellarRelayer";
export type {
  StellarRelayerOptions,
  StellarRelayKind,
} from "./chains/stellar/StellarRelayer";
export {
  LocalDeviceUnwrapKey,
  deviceSlotId,
} from "./chains/stellar/DeviceUnwrapKey";
export type { DeviceUnwrapKey } from "./chains/stellar/DeviceUnwrapKey";
export { WebCryptoDeviceUnwrapKey } from "./chains/stellar/WebCryptoDeviceUnwrapKey";
export type { WebCryptoUnwrapKeyOptions } from "./chains/stellar/WebCryptoDeviceUnwrapKey";
export { PasskeyPrf } from "./chains/stellar/PasskeyPrf";
export type { PasskeyPrfOptions, PasskeyPrfEnrollParams } from "./chains/stellar/PasskeyPrf";
export {
  deriveStellarAddress,
  deriveStellarMasterKeypair,
  generateControlKey,
} from "./chains/stellar/keys";
export {
  generateDEK,
  sealControlSeed,
  openControlSeed,
  wrapDEK,
  unwrapDEK,
  eciesWrapDEK,
  eciesUnwrapDEK,
  derivePasskeyKEK,
  deriveRecoveryKEK,
} from "./chains/stellar/envelope";
export {
  toDataEntries,
  fromDataEntries,
  type AccountEnvelope,
} from "./chains/stellar/datamap";

// Low-level crypto / encoding (advanced use)
export { signatureToFelts, recoverYParity } from "./crypto/signature";
export { PasskeySigner } from "./signer/PasskeySigner";
export type {
  PasskeySignerOptions,
  PasskeyEnrollParams,
  EnrolledPasskey,
} from "./signer/PasskeySigner";
export type { PasskeyAssertion } from "./crypto/webauthn";
export {
  base64urlEncode,
  webauthnDigest,
  recoverCandidatePublicKeys,
  batchChallenge,
  lowS,
} from "./crypto/webauthn";
export {
  u256ToFelts,
  bytesToBigInt,
  bytesToHex,
  hexToBytes,
  bigIntTo32Bytes,
} from "./crypto/encoding";
