import { Keypair, PublicKey, TransactionInstruction } from "@solana/web3.js";
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
 * Verifies the per-`execute()` `sponsored` flag on `CavosSolana`. The device
 * signature lives inside the secp256r1 precompile instruction (NOT a Solana tx
 * signature), so the only thing that flips between modes is who pays the fee:
 * the relayer (sponsored) vs the configured `feePayer` (self-funded).
 *
 * We bypass `connect()` (which needs the network) by constructing the instance
 * via the private constructor and a stub adapter.
 */
function makeWallet(opts: { relayer?: SolanaRelayer; feePayer?: Keypair }): CavosSolana {
  const stubAdapter = {
    buildExecuteTransfer: async () => [
      new TransactionInstruction({
        programId: new PublicKey("FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ"),
        keys: [],
        data: Buffer.from([0]),
      }),
    ],
  } as any;
  const connection = {} as any;
  // Private constructor: cast to access it without going through connect().
  const Ctor = CavosSolana as any as new (
    ...args: any[]
  ) => CavosSolana;
  return new Ctor(
    { userId: "u1" },
    new PublicKey("11111111111111111111111111111112").toBase58(),
    "ready",
    connection,
    stubAdapter,
    { x: 1n, y: 2n },
    opts.relayer,
    opts.feePayer,
  );
}

describe("CavosSolana.execute — sponsored flag", () => {
  afterEach(() => jest.restoreAllMocks());

  it("routes to the relayer by default (sponsored: true)", async () => {
    const relayer = { send: jest.fn().mockResolvedValue("relayerSig") } as unknown as SolanaRelayer;
    const wallet = makeWallet({ relayer });
    const sig = await wallet.execute(1n, "AnyDest");
    expect(sig).toBe("relayerSig");
    expect((relayer as any).send).toHaveBeenCalledTimes(1);
  });

  it("routes to the feePayer when { sponsored: false }", async () => {
    const relayer = { send: jest.fn().mockResolvedValue("relayerSig") } as unknown as SolanaRelayer;
    const feePayer = Keypair.generate();
    const wallet = makeWallet({ relayer, feePayer });
    confirmMock.mockClear();
    const sig = await wallet.execute(1n, "AnyDest", { sponsored: false });
    expect(sig).toBe("selfFundedSig");
    expect(confirmMock).toHaveBeenCalledTimes(1);
    expect((relayer as any).send).not.toHaveBeenCalled();
  });

  it("throws a clear error when self-funded but no feePayer is configured", async () => {
    const relayer = { send: jest.fn() } as unknown as SolanaRelayer;
    const wallet = makeWallet({ relayer });
    await expect(wallet.execute(1n, "AnyDest", { sponsored: false })).rejects.toThrow(
      /self-fund.*feePayer/,
    );
    expect((relayer as any).send).not.toHaveBeenCalled();
  });
});
