import type { Chain } from "../Cavos";
import type { CavosConfig } from "./CavosProvider";

/**
 * Pick the config for the chain a wallet lives on.
 *
 * A device signer exists on exactly one chain. Anything that arrives holding a
 * `network` — most often a `DeviceRemovalRequest` from a revocation email — is
 * scoped to that chain, and mounting `CavosProvider` with a different one asks
 * the wrong ledger whether a key it has never seen is authorized. The answer is
 * no, and the SDK reports "that device is not an authorized signer of this
 * wallet", which reads like the device is already gone rather than like the
 * question went to the wrong place.
 *
 * That failure is easy to write by accident: an app with one chain hardcodes
 * its config, adds a second chain later, and the revocation page keeps asking
 * the first one. This exists so nobody has to discover it the hard way.
 *
 * Chains report `network` in different shapes — `solana-devnet`,
 * `stellar-testnet`, but a bare `testnet` or `mainnet` for Starknet — so the
 * chain is taken from the prefix and Starknet is the fallback rather than a
 * listed case. A lookup table would go quietly wrong the day one of them
 * changes.
 *
 * @example
 * const config = configForNetwork(request.network, [
 *   starknetConfig, solanaConfig, stellarConfig,
 * ]);
 * return <CavosProvider config={config}>…</CavosProvider>;
 */
export function configForNetwork(
  network: string | undefined | null,
  configs: CavosConfig[],
): CavosConfig {
  if (configs.length === 0) {
    throw new Error("kit/react: configForNetwork needs at least one config");
  }

  const chain = chainForNetwork(network);
  const match = configs.find((config) => (config.chain ?? "starknet") === chain);
  if (match) return match;

  // Returning some other chain's config would produce the exact confusing
  // failure this function exists to prevent, so say what is missing instead.
  throw new Error(
    `kit/react: no config for chain "${chain}" (network "${network ?? "unset"}"). ` +
      `Pass the config for that chain, or check the wallet this request belongs to.`,
  );
}

/** The chain a `wallets.network` value belongs to. */
export function chainForNetwork(network: string | undefined | null): Chain {
  if (network?.startsWith("solana")) return "solana";
  if (network?.startsWith("stellar")) return "stellar";
  // Starknet records a bare `testnet` / `mainnet`, and is the original chain,
  // so it is the default rather than a prefix match.
  return "starknet";
}
