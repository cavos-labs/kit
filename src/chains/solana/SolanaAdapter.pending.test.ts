import { Buffer } from "buffer";
import { SolanaAdapter } from "./SolanaAdapter";

/**
 * `schedule_social_recovery` refuses to overwrite a live authorization, so a run
 * that scheduled but never finalized locks every retry out with
 * RecoveryAlreadyPending until it expires. Reading that state is what lets the
 * flow resume instead of failing — and reading it means getting the account
 * layout exactly right, which is what these tests pin.
 *
 * Layout after the 8-byte discriminator: device_account(32), recovery_pubkey(33),
 * delay_seconds(4), policy_hash(32), recovery_nonce(8), pending(1),
 * pending_signer(33), ready_at(8), expires_at(8).
 */
describe("SolanaAdapter.pendingSocialRecovery", () => {
  const account = "11111111111111111111111111111112";
  const PENDING_OFFSET = 8 + 32 + 33 + 4 + 32 + 8;

  function configAccount(opts: {
    pending: boolean;
    signer?: Uint8Array;
    readyAt?: number;
    expiresAt?: number;
  }) {
    const data = Buffer.alloc(PENDING_OFFSET + 1 + 33 + 8 + 8 + 1);
    data[PENDING_OFFSET] = opts.pending ? 1 : 0;
    if (opts.signer) Buffer.from(opts.signer).copy(data, PENDING_OFFSET + 1);
    const view = new DataView(data.buffer, data.byteOffset, data.length);
    view.setBigInt64(PENDING_OFFSET + 34, BigInt(opts.readyAt ?? 0), true);
    view.setBigInt64(PENDING_OFFSET + 42, BigInt(opts.expiresAt ?? 0), true);
    return { data };
  }

  function adapterReturning(info: unknown) {
    const adapter = new SolanaAdapter({});
    (adapter as unknown as { requireConnection: () => unknown }).requireConnection = () => ({
      getAccountInfo: async () => info,
    });
    return adapter;
  }

  it("returns null when social recovery was never enrolled", async () => {
    expect(await adapterReturning(null).pendingSocialRecovery(account)).toBeNull();
  });

  it("returns null when nothing is pending", async () => {
    const adapter = adapterReturning(configAccount({ pending: false }));
    expect(await adapter.pendingSocialRecovery(account)).toBeNull();
  });

  it("reads the pending signer and both timestamps", async () => {
    const signer = Uint8Array.from({ length: 33 }, (_, i) => (i + 7) % 251);
    const adapter = adapterReturning(
      configAccount({ pending: true, signer, readyAt: 1_700_000_000, expiresAt: 1_700_003_600 }),
    );

    const pending = await adapter.pendingSocialRecovery(account);
    expect(pending).not.toBeNull();
    expect(Array.from(pending!.signerCompressed)).toEqual(Array.from(signer));
    expect(pending!.readyAt).toBe(1_700_000_000);
    expect(pending!.expiresAt).toBe(1_700_003_600);
  });

  it("does not confuse the pending flag with the nonce that precedes it", async () => {
    // A non-zero nonce sits in the 8 bytes right before `pending`; reading one
    // byte off would report a pending recovery that does not exist.
    const acct = configAccount({ pending: false });
    new DataView(acct.data.buffer, acct.data.byteOffset, acct.data.length).setBigUint64(
      8 + 32 + 33 + 4 + 32,
      42n,
      true,
    );
    const adapter = adapterReturning(acct);
    expect(await adapter.pendingSocialRecovery(account)).toBeNull();
  });
});
