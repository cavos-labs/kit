import { StellarRelayer } from "./StellarRelayer";

describe("StellarRelayer", () => {
  afterEach(() => jest.restoreAllMocks());

  it("fetches the fee payer with app_id so the backend can isolate the org", async () => {
    const fetchMock = jest.spyOn(global, "fetch" as any).mockResolvedValue({
      ok: true,
      json: async () => ({ fee_payer: "GABC", sequence: "1" }),
    } as any);

    const relayer = new StellarRelayer({
      baseUrl: "https://cavos.test",
      appId: "app-grantfox",
      network: "stellar-mainnet",
    });
    const src = await relayer.getSource();
    expect(src).toBe("GABC");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("network=stellar-mainnet");
    expect(url).toContain("app_id=app-grantfox");
  });

  it("does not cache the sequence, but does cache the address", async () => {
    const fetchMock = jest.spyOn(global, "fetch" as any).mockResolvedValue({
      ok: true,
      json: async () => ({ fee_payer: "GABC", sequence: "7" }),
    } as any);

    const relayer = new StellarRelayer({
      baseUrl: "https://cavos.test",
      appId: "app-1",
      network: "stellar-testnet",
    });
    expect(await relayer.getSource()).toBe("GABC");
    expect(await relayer.getSource()).toBe("GABC");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await relayer.fetchSourceAccount();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
