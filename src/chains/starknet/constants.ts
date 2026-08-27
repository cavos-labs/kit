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

/** Universal Deployer Contract (same address on mainnet & sepolia). */
export const UDC_ADDRESS =
  "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf";

/** Cavos-hosted SNIP-29 paymaster (same service @cavos/react uses). */
export const CAVOS_PAYMASTER_URL: Record<StarknetNetwork, string> = {
  sepolia: "https://sepolia-paymaster.cavos.xyz",
  mainnet: "https://paymaster.cavos.xyz",
};

/**
 * DeviceAccount class hash, per network. Populated from
 * `account-contracts/starknet/deployments/<network>.json` after declaring.
 *
 * Sepolia re-declared 2026-08-27:
 *   - `constructor(app_namespace, pub_x, pub_y)` registers the first device
 *     signer, so the pubkey is part of the address and nobody else can claim it.
 *   - `initialize` is GONE, and with it the uninitialized window: no unsigned
 *     __validate__ / is_valid_signature bypass, no __execute__ selector guard.
 *   - Addresses under the previous class are identity-derived and are NOT
 *     migrated; the Cavos registry is the source of truth for user -> address.
 * Mainnet still runs the prior class until it is re-declared.
 */
export const DEVICE_ACCOUNT_CLASS_HASH: Record<StarknetNetwork, string> = {
  sepolia: "0x10716331f5880dd2778cbb6cff6d825e9f5441dcf9dbc8746e58042590aa621",
  mainnet: "0x1840aded59e8a0d2b440a134cb9079a7fc11b06c77f58ed189ab436a034ca6a",
};
