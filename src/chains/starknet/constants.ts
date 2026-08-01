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
 * Sepolia re-declared 2026-08-01:
 *   - Deploy attestation REMOVED — `initialize` takes only the device pubkey.
 *   - `is_valid_signature` returns VALIDATED pre-init so the SNIP-9 outside-
 *     execution path (used by the paymaster's `deploy_and_invoke`) can carry
 *     the `initialize` call before any signer is registered. `__execute__`
 *     still enforces that ONLY `initialize` runs in that state.
 *   - Adds a separate hardware-isolated social-recovery authority with nonce,
 *     expiry, cancellation and contract-enforced timelock.
 * Mainnet still runs the prior class (with attestation) until it is re-declared.
 */
export const DEVICE_ACCOUNT_CLASS_HASH: Record<StarknetNetwork, string> = {
  sepolia: "0x03f430a93dc4436ce2ba4a78f2ae00e10a40cd8df653516a14612df0275420a6",
  mainnet: "0x1840aded59e8a0d2b440a134cb9079a7fc11b06c77f58ed189ab436a034ca6a",
};
