import { recoverHardwareIsolatedDevice } from "./SocialRecoveryCoordinator";

/**
 * Adding a device on Solana used to cost two transactions: schedule, then
 * finalize. With no timelock there is nothing to wait for between them, and the
 * second relay round trip was roughly half the wall-clock time of the whole
 * operation.
 *
 * What must not change is the timelock itself. These tests pin the rule: batch
 * only when the delay is zero, never otherwise.
 */

const SIGNED = {
  chain: "solana" as const,
  message_b64: "AAEC",
  signature_b64: "AwQF",
  recovery_pubkey_compressed_b64: "BgcI",
  recovery_nonce: "1",
  expires_at: 9_999_999_999,
};

function walletDouble(delaySeconds: number) {
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
    delaySeconds,
  };
}

function clientDouble() {
  return {
    recover: async () => ({
      sessionId: "s",
      result: { result: "recovered", authorizations: [SIGNED] },
    }),
  } as any;
}

const credential = { idToken: "t", tokenFingerprint: "f" } as any;

describe("adding a device on Solana", () => {
  it("uses one transaction when there is no timelock", async () => {
    const { wallet, calls } = walletDouble(0);

    const outcome = await recoverHardwareIsolatedDevice({
      client: clientDouble(),
      wallet,
      credential,
      network: "testnet",
      delaySeconds: 0,
    });

    expect(calls).toEqual(["scheduleAndFinalize"]);
    expect(outcome.finalized).toBe(true);
    // Both fields report the same signature: there is only one transaction.
    expect(outcome.scheduleTransaction).toBe("sig-batched");
    expect(outcome.finalizeTransaction).toBe("sig-batched");
  });

  it("still schedules and waits when a timelock is configured", async () => {
    const { wallet, calls } = walletDouble(3600);

    const outcome = await recoverHardwareIsolatedDevice({
      client: clientDouble(),
      wallet,
      credential,
      network: "testnet",
      delaySeconds: 3600,
    });

    // Batching must never collapse a real delay: the caller has to come back
    // and finalize after readyAt.
    expect(calls).toEqual(["schedule"]);
    expect(calls).not.toContain("scheduleAndFinalize");
    expect(outcome.finalized).toBe(false);
    expect(outcome.finalizeTransaction).toBeUndefined();
    expect(outcome.readyAt).toBeGreaterThan(Math.floor(Date.now() / 1000) + 3000);
  });
});
