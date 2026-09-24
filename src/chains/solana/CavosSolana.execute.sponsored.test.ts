import { Keypair, PublicKey } from "@solana/web3.js";
import { CavosSolana } from "./CavosSolana";
import type { SolanaRelayer } from "./SolanaRelayer";

/**
 * Verifies the per-`execute()` `sponsored` flag on `CavosSolana`. There are two
 * routes and only two: the relayer pays (`sponsored: true`), or the wallet pays
 * its own fee from its own SOL balance (the default).
 */
const SELF = new PublicKey("11111111111111111111111111111112");

/** The constructor is private and takes an options object; tests reach it directly. */
function build(init: Record<string, unknown>): CavosSolana {
  const Ctor = CavosSolana as unknown as new (i: Record<string, unknown>) => CavosSolana;
  return new Ctor({ identity: { userId: "u1" }, address: SELF.toBase58(), status: "ready", ...init });
}

function makeWallet(opts: { relayer?: SolanaRelayer; connection?: unknown }): CavosSolana {
  const spend = {
    address: () => SELF.toBase58(),
    publicKeyRaw: () => SELF.toBytes(),
    signTransaction: async () => new Uint8Array(64),
    signMessage: async () => new Uint8Array(64),
  };
  const connection =
    opts.connection ??
    ({
      getLatestBlockhash: async () => ({
        blockhash: "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
        lastValidBlockHeight: 1,
      }),
    } as any);
  return build({ connection, spend, relayer: opts.relayer });
}

function selfPayConnection() {
  return {
    getLatestBlockhash: jest.fn().mockResolvedValue({
      blockhash: "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
      lastValidBlockHeight: 42,
    }),
    sendRawTransaction: jest.fn().mockResolvedValue("selfFundedSig"),
    confirmTransaction: jest.fn().mockResolvedValue({ value: { err: null } }),
  };
}

describe("CavosSolana.execute — sponsored flag", () => {
  it("pays its own fee by default, without any relayer call", async () => {
    const relayer = {
      getFeePayer: jest.fn(),
      sendSigned: jest.fn(),
    } as unknown as SolanaRelayer;
    const connection = selfPayConnection();
    const wallet = makeWallet({ relayer, connection });

    const sig = await wallet.execute(1n, Keypair.generate().publicKey.toBase58());

    expect(sig).toBe("selfFundedSig");
    expect(connection.sendRawTransaction).toHaveBeenCalledTimes(1);
    expect(connection.confirmTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ signature: "selfFundedSig", lastValidBlockHeight: 42 }),
      "confirmed",
    );
    expect((relayer as any).sendSigned).not.toHaveBeenCalled();
    expect((relayer as any).getFeePayer).not.toHaveBeenCalled();
  });

  it("pays its own fee with an explicit { sponsored: false }", async () => {
    const connection = selfPayConnection();
    const wallet = makeWallet({ connection });

    const sig = await wallet.execute(1n, Keypair.generate().publicKey.toBase58(), { sponsored: false });

    expect(sig).toBe("selfFundedSig");
    expect(connection.sendRawTransaction).toHaveBeenCalledTimes(1);
  });

  it("self-funding needs no relayer at all", async () => {
    const connection = selfPayConnection();
    const wallet = makeWallet({ connection });
    await expect(
      wallet.execute(1n, Keypair.generate().publicKey.toBase58()),
    ).resolves.toBe("selfFundedSig");
  });

  it("routes to the relayer when { sponsored: true }", async () => {
    const relayer = {
      getFeePayer: jest.fn().mockResolvedValue(Keypair.generate().publicKey),
      sendSigned: jest.fn().mockResolvedValue("relayerSig"),
    } as unknown as SolanaRelayer;
    const wallet = makeWallet({ relayer });

    const sig = await wallet.execute(1n, Keypair.generate().publicKey.toBase58(), { sponsored: true });

    expect(sig).toBe("relayerSig");
    expect((relayer as any).sendSigned).toHaveBeenCalledTimes(1);
  });

  it("throws a clear error when sponsored but no relayer is configured", async () => {
    const wallet = makeWallet({});
    await expect(
      wallet.execute(1n, Keypair.generate().publicKey.toBase58(), { sponsored: true }),
    ).rejects.toThrow(/cannot sponsor.*no relayer/);
  });
});
