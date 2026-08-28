import { describe, expect, it } from "@jest/globals";
import { passkeyEnrolmentTargets } from "./passkeyEnrolmentTargets";

/**
 * Which wallets a passkey enrolment writes to.
 *
 * Writing to every configured chain buys gas on chains the user may never
 * touch; writing to none leaves the key remembered in the tab, which a refresh
 * wipes. The rule is: wherever the account already exists, plus exactly one
 * that does not — so there is always somewhere to check a recovered key
 * against, and never a second deploy nobody asked for.
 */
type W = {
  chain: string;
  status: "undeployed" | "ready" | "needs-device-approval";
  addApprover: () => Promise<{ transactionHash?: string }>;
};

const wallet = (chain: string, status: W["status"]): W => ({
  chain,
  status,
  addApprover: async () => ({}),
});

const targets = (wallets: W[], selectedChain: string) =>
  passkeyEnrolmentTargets(wallets, selectedChain).map((w) => w.chain);

const fresh: W[] = [
  wallet("starknet", "undeployed"),
  wallet("solana", "undeployed"),
  wallet("stellar", "undeployed"),
];

describe("enrolling a passkey", () => {
  it("deploys exactly one chain on a brand-new account", () => {
    expect(targets(fresh, "solana")).toEqual(["solana"]);
  });

  it("deploys nothing when the user is on Stellar", () => {
    // Stellar keeps a secret, not a key, so there is nothing to write there —
    // and reaching for another chain would deploy a whole account on one the
    // user never asked about. A chain that comes later settles the key with a
    // second assertion instead.
    expect(targets(fresh, "stellar")).toEqual([]);
  });

  it("deploys the chain the user is actually on", () => {
    expect(targets(fresh, "starknet")).toEqual(["starknet"]);
  });

  it("writes to every chain that already exists", () => {
    // Free: no deploy, just the approver call.
    const mixed = [wallet("starknet", "ready"), wallet("solana", "ready"), wallet("stellar", "ready")];
    expect(targets(mixed, "starknet")).toEqual(["starknet", "solana"]);
  });

  it("does not deploy a second chain when one already exists", () => {
    const mixed = [
      wallet("starknet", "ready"),
      wallet("solana", "undeployed"),
      wallet("stellar", "undeployed"),
    ];
    expect(targets(mixed, "solana")).toEqual(["starknet"]);
  });

  it("never targets Stellar, which holds a secret and not a key", () => {
    expect(targets(fresh, "stellar")).not.toContain("stellar");
  });
});
