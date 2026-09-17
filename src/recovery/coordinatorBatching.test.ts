import { recoverHardwareIsolatedDevice } from "./SocialRecoveryCoordinator";

/**
 * Native Solana and Stellar restore the spend key at connect. Adding this
 * device is not a scheduled on-chain authority. A delay_seconds setting from
 * the PDA era must not create a Horizon extra or a program schedule.
 */

function walletDouble() {
  const calls: string[] = [];
  return {
    calls,
    wallet: {
      chain: "solana",
      address: "11111111111111111111111111111111",
      publicKey: { x: 1n, y: 2n },
      socialRecoveryNonce: async () => 1n,
      pendingSocialRecovery: async () => null,
      pendingRecoveryIsForThisDevice: async () => false,
      scheduleSocialRecovery: async () => {
        calls.push("schedule");
        return "sig-schedule";
      },
      finalizeSocialRecovery: async () => {
        calls.push("finalize");
        return "sig-finalize";
      },
      scheduleAndFinalizeSocialRecovery: async () => {
        calls.push("scheduleAndFinalize");
        return "sig-batched";
      },
    } as any,
  };
}

function clientDouble() {
  return {
    recover: async () => {
      throw new Error("native recover must not open an authorization job");
    },
  } as any;
}

const credential = { idToken: "t", tokenFingerprint: "f" } as any;

describe("adding a device on native Solana", () => {
  it("does not schedule an on-chain authority", async () => {
    const { wallet, calls } = walletDouble();
    const outcome = await recoverHardwareIsolatedDevice({
      client: clientDouble(),
      wallet,
      credential,
      network: "testnet",
      delaySeconds: 0,
    });
    expect(calls).toEqual([]);
    expect(outcome.finalized).toBe(true);
  });

  it("still does not schedule when a leftover timelock is configured", async () => {
    const { wallet, calls } = walletDouble();
    const outcome = await recoverHardwareIsolatedDevice({
      client: clientDouble(),
      wallet,
      credential,
      network: "testnet",
      delaySeconds: 3600,
    });
    expect(calls).toEqual([]);
    expect(outcome.finalized).toBe(true);
  });
});
