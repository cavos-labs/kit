import { PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import { SolanaRelayer } from "./SolanaRelayer";

const RELAYER = new PublicKey("11111111111111111111111111111112");
const BLOCKHASH = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

function fakeConnection() {
  return {
    getLatestBlockhash: jest.fn().mockResolvedValue({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 100,
    }),
  } as any;
}

describe("SolanaRelayer", () => {
  afterEach(() => jest.restoreAllMocks());

  it("fetches and caches the relayer fee payer", async () => {
    const fetchMock = jest
      .spyOn(global, "fetch" as any)
      .mockResolvedValue({ ok: true, json: async () => ({ fee_payer: RELAYER.toBase58() }) } as any);

    const relayer = new SolanaRelayer({
      baseUrl: "https://cavos.test",
      appId: "app-1",
      network: "solana-devnet",
      connection: fakeConnection(),
    });
    const fp1 = await relayer.getFeePayer();
    const fp2 = await relayer.getFeePayer();
    expect(fp1.toBase58()).toBe(RELAYER.toBase58());
    expect(fp2).toBe(fp1);
    expect(fetchMock).toHaveBeenCalledTimes(1); // cached
  });

  it("sends a tx with fee payer = relayer and posts the serialized tx", async () => {
    let postedBody: any;
    const fetchMock = jest.spyOn(global, "fetch" as any).mockImplementation((url: any, init?: any) => {
      if (!init) {
        return Promise.resolve({ ok: true, json: async () => ({ fee_payer: RELAYER.toBase58() }) } as any);
      }
      postedBody = JSON.parse(init.body);
      return Promise.resolve({ ok: true, json: async () => ({ signature: "sigABC" }) } as any);
    });

    const relayer = new SolanaRelayer({
      baseUrl: "https://cavos.test",
      appId: "app-42",
      network: "solana-devnet",
      connection: fakeConnection(),
    });

    const ix = new TransactionInstruction({
      programId: new PublicKey("FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ"),
      keys: [],
      data: Buffer.from([1, 2, 3]),
    });
    const sig = await relayer.send([ix]);

    expect(sig).toBe("sigABC");
    expect(postedBody.app_id).toBe("app-42");
    expect(postedBody.network).toBe("solana-devnet");
    // The serialized tx must carry the relayer as fee payer and the instruction.
    const tx = Transaction.from(Buffer.from(postedBody.transaction, "base64"));
    expect(tx.feePayer?.toBase58()).toBe(RELAYER.toBase58());
    expect(tx.instructions[0].programId.toBase58()).toBe(
      "FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ"
    );
    expect(fetchMock).toHaveBeenCalled();
  });
});
