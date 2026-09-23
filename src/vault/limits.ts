/** What happens to a transaction the limits do not cover. */
export type OverLimit = "ask" | "block" | "sign";

/**
 * A cap for one asset, in whole units as a person writes them ("0.5").
 * `asset` is "SOL", "XLM", a Solana mint, a Stellar "CODE:ISSUER", or on
 * Starknet one of "ETH", "STRK", "USDC".
 */
export interface VaultLimit {
  chain: "solana" | "stellar" | "starknet";
  asset: string;
  perTx: string;
  perDay: string;
}

/** Set per app in the Cavos dashboard and read by the vault from Cavos, never from the app. */
export interface VaultPolicy {
  overLimit: OverLimit;
  limits: VaultLimit[];
}

/** Used when the app's policy cannot be read: nothing is signed without the user. */
export const STRICT_POLICY: VaultPolicy = { overLimit: "ask", limits: [] };
