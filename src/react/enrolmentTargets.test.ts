import { describe, expect, it } from "@jest/globals";
import { decideSocialRecovery } from "./socialRecoveryDecision";

/**
 * A session holds a wallet per chain and only one of them is on screen —
 * `chains[0]` after a login, whatever the user happened to be using before.
 * Enrolment ran on that one alone, so a wallet the user had deployed on another
 * chain stayed unrecoverable, and nothing said so until a second device tried
 * to restore it and was told the wallet has no recovery set up.
 */
describe("choosing which wallets to enrol", () => {
  const enrolled = new Set<string>();
  const targets = (
    wallets: { chain: string; address: string; status: Parameters<typeof decideSocialRecovery>[0] }[],
  ) =>
    wallets
      .filter(
        (w) => decideSocialRecovery(w.status, enrolled.has(`${w.chain}:${w.address}`)).action === "enroll",
      )
      .map((w) => w.chain);

  const session = [
    { chain: "starknet", address: "0x1", status: "ready" as const },
    { chain: "solana", address: "sol1", status: "ready" as const },
    { chain: "stellar", address: "G1", status: "undeployed" as const },
  ];

  it("takes every deployed wallet, not just the visible one", () => {
    expect(targets(session)).toEqual(["starknet", "solana"]);
  });

  it("leaves an undeployed wallet for its own first transaction", () => {
    // There is no account on-chain yet to enrol an authority against.
    expect(targets(session)).not.toContain("stellar");
  });

  it("skips the chains already enrolled and keeps the rest", () => {
    // The case that hid the bug: Starknet enrolled on an earlier login, so the
    // one wallet the old code looked at had nothing to do and it stopped there.
    enrolled.add("starknet:0x1");
    expect(targets(session)).toEqual(["solana"]);
    enrolled.clear();
  });
});
