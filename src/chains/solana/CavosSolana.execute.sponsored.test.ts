import { Keypair, PublicKey } from "@solana/web3.js";
import { CavosSolana } from "./CavosSolana";
import type { SolanaRelayer } from "./SolanaRelayer";

// `sendAndConfirmTransaction` is captured at module load by CavosSolana, so we
// mock it before the wallet imports resolve. The factory keeps every other
// export of @solana/web3.js intact (auto-mock + manual override).
const confirmMock = jest.fn().mockResolvedValue("selfFundedSig");
jest.mock("@solana/web3.js", () => {
  const actual = jest.requireActual("@solana/web3.js");
  return {
    ...actual,
    sendAndConfirmTransaction: (...args: unknown[]) => confirmMock(...args),
  };
});

/**
 * Verifies the per-`execute()` `sponsored` flag on `CavosSolana`.
 * The spend key signs the Solana message; the relayer is only the fee payer.
 */
function makeWallet(opts: { relayer?: SolanaRelayer; feePayer?: Keypair }): CavosSolana {
  const spend = {
    address: () => new PublicKey("11111111111111111111111111111112").toBase58(),
    publicKeyRaw: () => new PublicKey("11111111111111111111111111111112").toBytes(),
    sign: async () => new Uint8Array(64),
  };
  const connection = {
    getLatestBlockhash: async () => ({ blockhash: "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi", lastValidBlockHeight: 1 }),
  } as any;
  const Ctor = CavosSolana as any as new (
    ...args: any[]
  ) => CavosSolana;
  return new Ctor(
    { userId: "u1" },
    new PublicKey("11111111111111111111111111111112").toBase58(),
    new Uint8Array(32),
    "ready",
    connection,
    { x: 1n, y: 2n },
    opts.relayer,
    opts.feePayer,
    undefined,
    spend,
  );
}

describe("CavosSolana.execute — sponsored flag", () => {
  afterEach(() => jest.restoreAllMocks());

  it("routes to the relayer by default (sponsored: true)", async () => {
    const dest = Keypair.generate().publicKey.toBase58();
    const relayer = {
      getFeePayer: jest.fn().mockResolvedValue(Keypair.generate().publicKey),
      sendSigned: jest.fn().mockResolvedValue("relayerSig"),
    } as unknown as SolanaRelayer;
    const wallet = makeWallet({ relayer });
    const sig = await wallet.execute(1n, dest);
    expect(sig).toBe("relayerSig");
    expect((relayer as any).sendSigned).toHaveBeenCalledTimes(1);
  });

  it("routes to the feePayer when { sponsored: false }", async () => {
    const relayer = {
      getFeePayer: jest.fn(),
      sendSigned: jest.fn().mockResolvedValue("relayerSig"),
    } as unknown as SolanaRelayer;
    const feePayer = Keypair.generate();
    const wallet = makeWallet({ relayer, feePayer });
    confirmMock.mockClear();
    const sig = await wallet.execute(1n, feePayer.publicKey.toBase58(), { sponsored: false });
    expect(sig).toBe("selfFundedSig");
    expect(confirmMock).toHaveBeenCalledTimes(1);
    expect((relayer as any).sendSigned).not.toHaveBeenCalled();
  });

  it("throws a clear error when self-funded but no feePayer is configured", async () => {
    const relayer = { getFeePayer: jest.fn(), sendSigned: jest.fn() } as unknown as SolanaRelayer;
    const wallet = makeWallet({ relayer });
    await expect(
      wallet.execute(1n, Keypair.generate().publicKey.toBase58(), { sponsored: false }),
    ).rejects.toThrow(/self-fund.*feePayer/);
    expect((relayer as any).sendSigned).not.toHaveBeenCalled();
  });
});
