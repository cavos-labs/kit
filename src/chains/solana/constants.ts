export const SOLANA_NETWORKS = {
  "solana-devnet": "https://api.devnet.solana.com",
  "solana-mainnet": "https://api.mainnet-beta.solana.com",
  "solana-localnet": "http://127.0.0.1:8899",
} as const;

export type SolanaNetwork = keyof typeof SOLANA_NETWORKS;
