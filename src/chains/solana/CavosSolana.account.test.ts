import bs58 from "bs58";
import { Keypair, Message, PublicKey } from "@solana/web3.js";
import { CavosSolana } from "./CavosSolana";

/**
 * The native-account surface: signing without submitting, readiness, and the
 * lamport amounts that reach the wire.
 */
const SELF = new PublicKey("11111111111111111111111111111112");
/** The constructor is private and takes an options object; tests reach it directly. */
function build(init: Record<string, unknown>): CavosSolana {
  const Ctor = CavosSolana as unknown as new (i: Record<string, unknown>) => CavosSolana;
  return new Ctor({ identity: { userId: "u1" }, address: SELF.toBase58(), status: "ready", ...init });
}

const BLOCKHASH = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

function makeWallet(opts: { spend?: unknown; connection?: unknown } = {}): CavosSolana {
  const spend =
    "spend" in opts
      ? opts.spend
      : {
          address: () => SELF.toBase58(),
          publicKeyRaw: () => SELF.toBytes(),
          sign: async () => new Uint8Array(64),
        };
  const connection =
    opts.connection ??
    ({
      getLatestBlockhash: async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 1 }),
    } as any);
  return build({ connection, spend });
}

describe("CavosSolana.signTransaction", () => {
  it("produces a message that compiles — the account is its own fee payer", async () => {
    const dest = Keypair.generate().publicKey;
    const wallet = makeWallet();

    // Regression: this threw "Transaction fee payer required" because the
    // transaction was compiled with no fee payer set.
    const signed = await wallet.signTransaction(5n, dest.toBase58());

    expect(signed.chain).toBe("solana");
    const message = Message.from(Buffer.from(signed.message));
    expect(message.accountKeys[0]!.toBase58()).toBe(SELF.toBase58());
    expect(message.recentBlockhash).toBe(BLOCKHASH);
    expect(signed.signature).toHaveLength(64);
  });

  it("carries lamport amounts above 2^53 without losing precision", async () => {
    // Number(amount) silently truncated here; SystemProgram.transfer takes a bigint.
    const amount = 9_007_199_254_740_993n; // 2^53 + 1
    const wallet = makeWallet();

    const signed = await wallet.signTransaction(amount, Keypair.generate().publicKey.toBase58());

    const message = Message.from(Buffer.from(signed.message));
    // SystemProgram transfer layout: u32 instruction index + u64 lamports (LE).
    const data = Buffer.from(bs58.decode(message.instructions[0]!.data));
    expect(data.readBigUInt64LE(4)).toBe(amount);
  });

  it("throws a clear error when this device holds no spend key", async () => {
    const wallet = makeWallet({ spend: undefined });
    await expect(
      wallet.signTransaction(1n, Keypair.generate().publicKey.toBase58()),
    ).rejects.toThrow(/no native spend key/);
  });
});

describe("CavosSolana readiness", () => {
  it("is ready — and deployed — when the spend key is present", async () => {
    const wallet = makeWallet();
    await expect(wallet.isReady()).resolves.toBe(true);
    expect(wallet.status).toBe("ready");
    expect(wallet.isDeployed).toBe(true);
  });

  it("is NOT ready without a spend key, and does not claim otherwise", async () => {
    // Regression: isReady() returned true unconditionally, so the provider's
    // approval poll exited on its first pass no matter the real state.
    const wallet = build({ connection: {} as any, status: "needs-device-approval" });

    await expect(wallet.isReady()).resolves.toBe(false);
    expect(wallet.status).toBe("needs-device-approval");
  });
});
