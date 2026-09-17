import { PublicKey } from "@solana/web3.js";
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

  it("posts a user-signed native tx without rewriting it as unsigned instructions", async () => {
    let postedBody: any;
    jest.spyOn(global, "fetch" as any).mockImplementation((url: any, init?: any) => {
      if (!init) {
        return Promise.resolve({ ok: true, json: async () => ({ fee_payer: RELAYER.toBase58() }) } as any);
      }
      postedBody = JSON.parse(init.body);
      return Promise.resolve({ ok: true, json: async () => ({ signature: "nativeSig" }) } as any);
    });

    const relayer = new SolanaRelayer({
      baseUrl: "https://cavos.test",
      appId: "app-42",
      network: "solana-devnet",
      connection: fakeConnection(),
    });
    const sig = await relayer.sendSigned(new Uint8Array([1, 2, 3, 4]));
    expect(sig).toBe("nativeSig");
    expect(postedBody.kind).toBe("native");
    expect(postedBody.transaction).toBe(Buffer.from([1, 2, 3, 4]).toString("base64"));
  });
});
