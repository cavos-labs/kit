/** Starknet network presets and well-known addresses for the kit. */

export const STARKNET_NETWORKS = {
  sepolia: {
    chainId: "0x534e5f5345504f4c4941", // SN_SEPOLIA
    rpcUrl: "https://api.cartridge.gg/x/starknet/sepolia",
  },
  mainnet: {
    chainId: "0x534e5f4d41494e", // SN_MAIN
    rpcUrl: "https://api.cartridge.gg/x/starknet/mainnet",
  },
} as const;

export type StarknetNetwork = keyof typeof STARKNET_NETWORKS;

/** Cavos-hosted SNIP-29 paymaster (same service @cavos/react uses). */
export const CAVOS_PAYMASTER_URL: Record<StarknetNetwork, string> = {
  sepolia: "https://sepolia-paymaster.cavos.xyz",
  mainnet: "https://paymaster.cavos.xyz",
};

/**
 * OpenZeppelin `AccountUpgradeable` v3.0.0 class hash (Scarb 2.13.1,
 * `--release`), declared on mainnet and Sepolia. Pinned forever: the account
 * address derives from it, and `ensureEnclave` clears the local wrap when the
 * derived address differs from the registered one. Later implementation changes go through the account's
 * `upgrade`, which keeps the address.
 */
export const OZ_ACCOUNT_CLASS_HASH =
  "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381";
