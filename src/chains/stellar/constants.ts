/** Classic-Stellar (`G…`) network configuration.
 *
 * This is now THE Stellar implementation in the kit (the Soroban `C…`
 * device-account path was removed — `G…` classic multisig is the default). Classic
 * Stellar uses Horizon (not the Soroban RPC) to load account state and submit
 * transactions. */

export const STELLAR_NETWORKS = {
  "stellar-testnet": {
    passphrase: "Test SDF Network ; September 2015",
  },
  "stellar-mainnet": {
    passphrase: "Public Global Stellar Network ; September 2015",
  },
} as const;

export type StellarNetwork = keyof typeof STELLAR_NETWORKS;

export const HORIZON_URL = {
  "stellar-testnet": "https://horizon-testnet.stellar.org",
  "stellar-mainnet": "https://horizon.stellar.org",
} as const;

/** Soroban RPC endpoints — used only for contract invocation (simulate, footprint,
 *  resource fees, submit). Classic account state/pay still goes through Horizon. */
export const SOROBAN_RPC_URL = {
  "stellar-testnet": "https://soroban-testnet.stellar.org",
  "stellar-mainnet": "https://mainnet.sorobanrpc.com",
} as const;

/** Native XLM has 7 decimals (stroops). */
export const XLM_DECIMALS = 7;
