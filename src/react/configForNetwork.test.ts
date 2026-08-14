import { chainForNetwork, configForNetwork } from "./configForNetwork";
import type { CavosConfig } from "./CavosProvider";

const starknet: CavosConfig = { appId: "a", chain: "starknet", network: "testnet" };
const solana: CavosConfig = { appId: "a", chain: "solana", network: "testnet" };
const stellar: CavosConfig = { appId: "a", chain: "stellar", network: "testnet" };
const all = [starknet, solana, stellar];

describe("chainForNetwork", () => {
  it("maps the shapes each chain actually reports", () => {
    // These are the real values from `wallets.network`, not invented ones.
    expect(chainForNetwork("solana-devnet")).toBe("solana");
    expect(chainForNetwork("solana-mainnet")).toBe("solana");
    expect(chainForNetwork("stellar-testnet")).toBe("stellar");
    expect(chainForNetwork("stellar-mainnet")).toBe("stellar");
    // Starknet records a bare environment, with no chain prefix.
    expect(chainForNetwork("testnet")).toBe("starknet");
    expect(chainForNetwork("mainnet")).toBe("starknet");
  });

  it("falls back to Starknet when the network is missing", () => {
    // Requests predating multi-chain carry no network; Starknet is where those
    // wallets are, so this keeps old revocation links working.
    expect(chainForNetwork(undefined)).toBe("starknet");
    expect(chainForNetwork(null)).toBe("starknet");
  });
});

describe("configForNetwork", () => {
  it("selects the config for the chain the wallet is on", () => {
    expect(configForNetwork("solana-devnet", all)).toBe(solana);
    expect(configForNetwork("stellar-testnet", all)).toBe(stellar);
    expect(configForNetwork("testnet", all)).toBe(starknet);
  });

  it("treats a config with no explicit chain as Starknet", () => {
    const implicit: CavosConfig = { appId: "a", network: "testnet" };
    expect(configForNetwork("testnet", [implicit])).toBe(implicit);
  });

  it("refuses rather than returning the wrong chain", () => {
    // Silently handing back a Starknet config for a Solana request is exactly
    // the bug this function prevents, so it must not be a fallback.
    expect(() => configForNetwork("solana-devnet", [starknet])).toThrow(
      /no config for chain "solana"/,
    );
    expect(() => configForNetwork("testnet", [])).toThrow(/at least one config/);
  });
});
