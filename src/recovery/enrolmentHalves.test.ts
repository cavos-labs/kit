import { describe, expect, it, jest } from "@jest/globals";
import { agreeRecoveryAuthority, writeRecoveryAuthority } from "./SocialRecoveryCoordinator";
import type { CavosWallet } from "../Cavos";
import type { SocialRecoveryClient } from "./SocialRecoveryClient";
import type { SocialRecoveryCredential } from "./SocialRecoveryCredential";

/**
 * Enrolment has two halves with incompatible deadlines. The enclave half needs
 * a login proof the enclave rejects once it is five minutes old; the chain half
 * needs an account that, under lazy deploy, does not exist until the user's
 * first transaction — ten minutes later, or tomorrow. Doing both at once meant
 * neither happened for anyone who did not transact immediately, and the only
 * symptom was a second device being told the wallet has no recovery.
 */
describe("the two halves of enrolment", () => {
  const result = {
    result: "enrolled",
    policy_hash_hex: `0x${"11".repeat(32)}`,
    recovery_pubkey_compressed_b64: Buffer.alloc(33, 2).toString("base64"),
    recovery_x_hex: "0x2",
    recovery_y_hex: "0x3",
  };

  const clientWith = (enroll: unknown) =>
    ({ enroll, confirmEnrollment: jest.fn(async () => {}) }) as unknown as SocialRecoveryClient;

  const starknetWallet = () =>
    ({
      chain: "starknet",
      address: "0x490662",
      enrollSocialRecovery: jest.fn(async () => ({ transactionHash: "0xtx" })),
    }) as unknown as CavosWallet;

  const credential = { tokenFingerprint: "fp" } as SocialRecoveryCredential;

  it("agrees an authority without touching the chain", async () => {
    // The half that must run at login, when there is no account yet.
    const wallet = starknetWallet();
    const enroll = jest.fn(async () => ({ sessionId: "s1", result }));
    const agreed = await agreeRecoveryAuthority({ client: clientWith(enroll), wallet, credential });

    expect(agreed.sessionId).toBe("s1");
    expect(wallet.enrollSocialRecovery).not.toHaveBeenCalled();
  });

  it("writes an agreed authority without a login proof", async () => {
    // The half that runs whenever the account finally exists. It takes no
    // credential at all — that is the whole point.
    const wallet = starknetWallet();
    const client = clientWith(jest.fn());
    const written = await writeRecoveryAuthority({
      client,
      wallet,
      authority: { sessionId: "s1", result: result as never },
      delaySeconds: 0,
    });

    expect(wallet.enrollSocialRecovery).toHaveBeenCalledTimes(1);
    expect(written.transactionHash).toBe("0xtx");
    expect(client.confirmEnrollment).toHaveBeenCalledWith("s1", "0xtx");
  });

  it("does not ask the enclave again when it writes", async () => {
    // The proof is long gone by then; asking again would fail for everyone who
    // took more than five minutes to transact.
    const enroll = jest.fn();
    const client = clientWith(enroll);
    await writeRecoveryAuthority({
      client,
      wallet: starknetWallet(),
      authority: { sessionId: "s1", result: result as never },
      delaySeconds: 0,
    });

    expect(enroll).not.toHaveBeenCalled();
  });
})
