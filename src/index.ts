/**
 * @cavos/kit — device-native accounts on Starknet, Solana, and Stellar.
 *
 * Every chain is native: the spend key is HKDF of a MasterDEK (enclave seal or
 * passkey PRF). Starknet is the standard OpenZeppelin account with a stark key,
 * Solana and Stellar use Ed25519. Recovery is off-chain; there is no on-chain
 * device list.
 */

// High-level entry point (Privy-like: log in -> ready, deployed, gasless wallet)
export { Cavos } from "./Cavos";
export type {
  ConnectOptions,
  ConnectStatus,
  Chain,
  NetworkEnv,
  CavosWallet,
} from "./Cavos";

// Auth / identity
export type { AuthProvider, Identity } from "./auth/AuthProvider";
export { StaticIdentity } from "./auth/AuthProvider";
export { CavosAuth } from "./auth/CavosAuth";
export type { CavosAuthOptions } from "./auth/CavosAuth";

// Off-chain user_id -> wallet map (multi-device recognition; backend-implemented)
export type { WalletRegistry, RegisteredWallet, RegisterResult } from "./registry/WalletRegistry";
export { InMemoryWalletRegistry } from "./registry/WalletRegistry";
export { HttpWalletRegistry } from "./registry/HttpWalletRegistry";
export type { HttpWalletRegistryOptions } from "./registry/HttpWalletRegistry";

export { generateRecoveryCode } from "./recovery/recoveryCode";
export {
  SocialRecoveryClient,
} from "./recovery/SocialRecoveryClient";
export type { SocialRecoveryCredential } from "./recovery/SocialRecoveryCredential";
export { createSocialRecoveryCredential } from "./recovery/SocialRecoveryCredential";
export type {
  AttestationPolicy,
  ChainAuthorization as SocialChainAuthorization,
  ProviderPolicy as SocialProviderPolicy,
  SocialRecoveryAction,
  SocialRecoveryClientOptions,
  SocialRecoveryProvider,
  SocialRecoveryResult,
} from "./recovery/SocialRecoveryClient";
export { DEFAULT_SOCIAL_RECOVERY_ATTESTATION } from "./recovery/attestationDefaults";
export type { EnclaveReleasePolicy } from "./recovery/nitro/release";

// Signers
export type { DevicePublicKey } from "./signer/DeviceSigner";
export type {
  PasskeyPrfProvider,
  PasskeyEnrollParams,
  PasskeyPrfEnrollResult,
} from "./signer/PasskeyProvider";

// Off-chain message signing + sign-without-submit
export type {
  MessageSignature,
  SignedTransaction,
  StarknetSignedTransaction,
  StellarSignedTransaction,
  SolanaSignedTransaction,
  SignatureCurve,
} from "./signing";
export { CAVOS_MESSAGE_PREFIX, prefixedMessageBytes } from "./signing";

// Chain adapters
export type {
  ChainCall,
  ExecuteOptions,
  FeeMode,
  SolanaExecuteOptions,
  SolanaFeeMode,
} from "./chains/ChainAdapter";
export { CavosStarknet } from "./chains/starknet/CavosStarknet";
export type { ConnectStarknetOptions } from "./chains/starknet/CavosStarknet";
export { parseStarknetPrivacyConfig } from "./chains/starknet/privacy/config";
export type { PrivacyFeeMode, PrivacyRelayConfig, StarknetPrivacyConfig } from "./chains/starknet/privacy/config";
export type {
  PrivacyOperations,
  PrivacyRequirement,
  PrivacyStatus,
  PrivacySubmission,
} from "./chains/starknet/privacy/session";
export { STARKNET_NETWORKS, CAVOS_PAYMASTER_URL, OZ_ACCOUNT_CLASS_HASH } from "./chains/starknet/constants";
export type { StarknetNetwork } from "./chains/starknet/constants";
export {
  starkKeyFromSeed,
  starkPublicKey,
  starknetAddressFromPublicKey,
  starknetAddressFromSeed,
} from "./chains/starknet/keys";
export { SOLANA_NETWORKS } from "./chains/solana/constants";
export type { SolanaNetwork } from "./chains/solana/constants";
export { CavosSolana } from "./chains/solana/CavosSolana";
export type { ConnectSolanaOptions, RecoverSolanaOptions, InstructionData, InstructionAccount } from "./chains/solana/CavosSolana";
export { SolanaRelayer } from "./chains/solana/SolanaRelayer";
export type { SolanaRelayerOptions } from "./chains/solana/SolanaRelayer";

// Stellar — classic `G…` multisig account (self-custodial, no backend/registry).
// This is THE Stellar implementation: the Soroban `C…` device-account path was
// removed in favour of classic G accounts (partner requirement + simpler model).
export { STELLAR_NETWORKS, HORIZON_URL, SOROBAN_RPC_URL, XLM_DECIMALS } from "./chains/stellar/constants";
export { TrustlessWorkEscrow, deployEscrow, buildEscrowScVal } from "./integrations/trustlesswork";
export type { EscrowInput, MilestoneInput, EscrowState } from "./integrations/trustlesswork";
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
export { generateControlKey, controlKeypairFromSeed } from "./chains/stellar/keys";
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
export {
  u256ToFelts,
  bytesToBigInt,
  bytesToHex,
  hexToBytes,
  bigIntTo32Bytes,
} from "./crypto/encoding";
export { VaultClient } from "./vault/VaultClient";
