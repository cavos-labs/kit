/** Cavos device-account program + Solana primitives. */

/** Deployed `cavos-device-account` program id (see account-contracts/solana). */
export const DEVICE_ACCOUNT_PROGRAM_ID =
  "FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ";

/** Native secp256r1 signature-verify precompile (SIMD-0075). */
export const SECP256R1_PROGRAM_ID =
  "Secp256r1SigVerify1111111111111111111111111";

/** PDA seed prefix, must match the program's `ACCOUNT_SEED`. */
export const ACCOUNT_SEED = "cavos-account";

/** Domain separators, must match the program's signed-message domains. */
export const DOMAIN_ADD = "cavos:add_signer:v1";
export const DOMAIN_REMOVE = "cavos:remove_signer:v1";
export const DOMAIN_TRANSFER = "cavos:transfer:v1";
/** Arbitrary execution (CPI). The signed message commits to sha256 of the
 *  canonical Borsh serialization of the instruction set — see `buildExecute`. */
export const DOMAIN_EXECUTE = "cavos:execute:v1";

/** secp256r1 (P-256) curve order, for low-S normalization. */
export const SECP256R1_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export const SOLANA_NETWORKS = {
  "solana-devnet": "https://api.devnet.solana.com",
  "solana-mainnet": "https://api.mainnet-beta.solana.com",
  "solana-localnet": "http://127.0.0.1:8899",
} as const;

export type SolanaNetwork = keyof typeof SOLANA_NETWORKS;
