/** Cavos device-account primitives on Stellar / Soroban. */

/**
 * Deployed `cavos-account-factory` contract id per network (see
 * account-contracts/stellar/deployments). The factory is the fixed deployer that
 * makes account addresses a deterministic function of (identity, device pubkey).
 */
export const FACTORY_CONTRACT_ID = {
  // Re-deployed 2026-07-01 with the passkey-approval device-account wasm (batched
  // multi-chain challenge). The factory pins the wasm hash immutably, so a new
  // wasm needs a new factory → new account addresses; testnet has no prod wallets.
  "stellar-testnet": "CBCJIODXIEBOXXD66KCUCF7ZDYJARKI4ZIVQOVWPULOBH5XGNCDP6W3I",
  // Set once the factory is deployed to mainnet (its address differs — network id
  // is part of contract-address derivation).
  "stellar-mainnet": "",
} as const;

/** Uploaded Wasm hash of `cavos-device-account` (informational / verification). */
export const DEVICE_ACCOUNT_WASM_HASH = {
  "stellar-testnet": "2671b085578e59a385ef5a5664e42f0450322fe3249539f588e1263ed5a31dce",
  "stellar-mainnet": "",
} as const;

export const STELLAR_NETWORKS = {
  "stellar-testnet": {
    rpcUrl: "https://soroban-testnet.stellar.org",
    passphrase: "Test SDF Network ; September 2015",
  },
  "stellar-mainnet": {
    rpcUrl: "https://soroban-rpc.mainnet.stellar.gateway.fm",
    passphrase: "Public Global Stellar Network ; September 2015",
  },
} as const;

export type StellarNetwork = keyof typeof STELLAR_NETWORKS;

/** Native XLM Stellar Asset Contract (SAC) id per network — the token the demo
 *  moves. Any SEP-41 token contract works; this is a convenience default. */
export const NATIVE_SAC_ID = {
  "stellar-testnet": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
  "stellar-mainnet": "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA",
} as const;
