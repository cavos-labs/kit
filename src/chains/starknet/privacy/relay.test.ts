import { PrivacyRelay, type RelayInvoke } from "./relay";
import type { PrivacyFeeMode } from "./config";

const FORWARDER = "0x75a1";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const POOL = "0x123";
const USER_FEE: PrivacyFeeMode = { mode: "sponsored", pool_fee: { paid_by: "user", token: STRK } };
const SPONSOR_FEE: PrivacyFeeMode = { mode: "sponsored", pool_fee: { paid_by: "sponsor" } };

function relay(result: unknown, options: { maxFee?: bigint; published?: bigint } = {}) {
  const requests: any[] = [];
  const instance = new PrivacyRelay({
    url: "https://relay.test",
    apiKey: () => "key",
    maxFee: options.maxFee ?? 100n,
    allowedFeeRecipients: [FORWARDER],
    publishedFee: async () => options.published ?? 50n,
    publishedFeeToken: STRK,
    fetch: (async (_url: string, init?: RequestInit) => {
      requests.push(JSON.parse(String(init?.body)));
      return { ok: true, status: 200, json: async () => ({ result }) } as Response;
    }) as unknown as typeof fetch,
  });
  return { instance, requests };
}

const withdraw = (overrides: Record<string, string> = {}) => ({
  fee_action: { type: "withdraw", recipient: FORWARDER, token: STRK, amount: "0x10", ...overrides },
  parameters: { version: "0x1" },
});

describe("relay quotes", () => {
  it("accepts a fee within every bound", async () => {
    const { instance } = relay(withdraw());
    const quote = await instance.quote(POOL, USER_FEE);
    expect(quote.feeAction).toEqual({ recipient: FORWARDER, token: `0x${BigInt(STRK).toString(16)}`, amount: 16n });
  });

  it("refuses a fee sent to a recipient the app did not list", async () => {
    const { instance } = relay(withdraw({ recipient: "0xbad" }));
    await expect(instance.quote(POOL, USER_FEE)).rejects.toThrow(/does not allow/);
  });

  it("refuses a fee above maxFee", async () => {
    const { instance } = relay(withdraw({ amount: "0x65" }));
    await expect(instance.quote(POOL, USER_FEE)).rejects.toThrow(/above the 100/);
  });

  it("refuses a pool fee above what the pool publishes", async () => {
    const { instance } = relay(withdraw({ amount: "0x40" }), { maxFee: 1000n, published: 50n });
    await expect(instance.quote(POOL, USER_FEE)).rejects.toThrow(/pool publishes/);
  });

  it("refuses a fee in a token the app did not choose", async () => {
    const { instance } = relay(withdraw({ token: "0x99" }));
    await expect(instance.quote(POOL, USER_FEE)).rejects.toThrow(/did not choose/);
  });

  it("refuses to withdraw a fee the sponsor was meant to pay", async () => {
    const { instance } = relay(withdraw());
    await expect(instance.quote(POOL, SPONSOR_FEE)).rejects.toThrow(/sponsor pays/);
  });

  it("returns no fee action when the sponsor pays", async () => {
    const { instance, requests } = relay({ fee_action: { type: "none" }, parameters: {} });
    expect((await instance.quote(POOL, SPONSOR_FEE)).feeAction).toBeNull();
    expect(requests[0].method).toBe("paymaster_buildTransaction");
    expect(requests[0].params.parameters).toEqual({ version: "0x1", fee_mode: SPONSOR_FEE });
  });
});

describe("relay approval typed data", () => {
  const invoke: RelayInvoke = {
    userAddress: "0xacc",
    chainId: "SN_SEPOLIA",
    calls: [{ to: "0x1", selector: "0x2", calldata: ["0x3", "0x4"] }],
  };
  const typed = (overrides: Record<string, unknown> = {}, domain: Record<string, unknown> = {}) => ({
    ...withdraw({ amount: "0x1" }),
    typed_data: {
      primaryType: "OutsideExecution",
      types: {},
      domain: { name: "Account.execute_from_outside", version: "2", chainId: "SN_SEPOLIA", revision: "1", ...domain },
      message: {
        Caller: FORWARDER,
        Nonce: "0x1",
        "Execute After": "0x1",
        "Execute Before": `0x${(Math.floor(Date.now() / 1000) + 600).toString(16)}`,
        Calls: [{ To: "0x1", Selector: "0x2", Calldata: ["0x3", "0x4"] }],
        ...overrides,
      },
    },
  });

  it("accepts the calls that were requested", async () => {
    const { instance } = relay(typed());
    expect((await instance.quote(POOL, USER_FEE, invoke)).typedData).toBeDefined();
  });

  it.each([
    ["another contract", { Calls: [{ To: "0x9", Selector: "0x2", Calldata: ["0x3", "0x4"] }] }, {}],
    ["another entrypoint", { Calls: [{ To: "0x1", Selector: "0x9", Calldata: ["0x3", "0x4"] }] }, {}],
    ["other arguments", { Calls: [{ To: "0x1", Selector: "0x2", Calldata: ["0x3", "0x5"] }] }, {}],
    ["an extra call", { Calls: [{ To: "0x1", Selector: "0x2", Calldata: ["0x3", "0x4"] }, { To: "0x1", Selector: "0x2", Calldata: [] }] }, {}],
    ["a caller that is not allowed", { Caller: "0xbad" }, {}],
    ["an expired signature", { "Execute Before": "0x1" }, {}],
    ["another chain", {}, { chainId: "SN_MAIN" }],
    ["another domain", {}, { name: "Other" }],
  ])("refuses %s", async (_name, message, domain) => {
    const { instance } = relay(typed(message, domain));
    await expect(instance.quote(POOL, USER_FEE, invoke)).rejects.toThrow(/nothing was signed/);
  });

  it("refuses a relay that returns nothing to sign", async () => {
    const { instance } = relay(withdraw());
    await expect(instance.quote(POOL, USER_FEE, invoke)).rejects.toThrow(/nothing to sign/);
  });
});
