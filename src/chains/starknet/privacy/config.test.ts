import { parseStarknetPrivacyConfig } from "./config";

const valid = {
  pool: "0x0123",
  prover: "https://prover.example.com/",
  discovery: "https://discovery.example.com",
  relay: {
    url: "https://relay.example.com",
    fee: { mode: "sponsored", pool_fee: { paid_by: "user", token: "0x04718f" } },
    maxFee: "1000000",
    allowedFeeRecipients: ["0x75a1"],
  },
};

describe("privacy config", () => {
  it("normalises a valid config", () => {
    expect(parseStarknetPrivacyConfig(valid)).toEqual({
      pool: "0x123",
      prover: "https://prover.example.com",
      discovery: "https://discovery.example.com",
      relay: {
        url: "https://relay.example.com",
        fee: { mode: "sponsored", pool_fee: { paid_by: "user", token: "0x4718f" } },
        maxFee: "1000000",
        allowedFeeRecipients: ["0x75a1"],
      },
    });
  });

  it("accepts the other fee modes, ohttp and an rpc url", () => {
    const parsed = parseStarknetPrivacyConfig({
      ...valid,
      ohttp: false,
      rpcUrl: "http://localhost:5050",
      relay: { ...valid.relay, fee: { mode: "default", gas_token: "0x1" } },
    });
    expect(parsed.ohttp).toBe(false);
    expect(parsed.rpcUrl).toBe("http://localhost:5050");
    expect(parsed.relay.fee).toEqual({ mode: "default", gas_token: "0x1" });
    expect(
      parseStarknetPrivacyConfig({ ...valid, relay: { ...valid.relay, fee: { mode: "sponsored", pool_fee: { paid_by: "sponsor" } } } }).relay.fee,
    ).toEqual({ mode: "sponsored", pool_fee: { paid_by: "sponsor" } });
  });

  it.each([
    ["a missing pool", { ...valid, pool: undefined }, /privacy\.pool/],
    ["a malformed pool", { ...valid, pool: "pool" }, /privacy\.pool/],
    ["a zero pool", { ...valid, pool: "0x0" }, /privacy\.pool/],
    ["an unknown field", { ...valid, extra: 1 }, /privacy\.extra/],
    ["a plain http prover", { ...valid, prover: "http://prover.example.com" }, /privacy\.prover.*https/],
    ["credentials in a url", { ...valid, discovery: "https://u:p@d.example.com" }, /credentials/],
    ["a non-boolean ohttp", { ...valid, ohttp: "yes" }, /privacy\.ohttp/],
    ["a numeric maxFee", { ...valid, relay: { ...valid.relay, maxFee: 5 } }, /maxFee/],
    ["a negative maxFee", { ...valid, relay: { ...valid.relay, maxFee: "-5" } }, /maxFee/],
    ["no fee recipients", { ...valid, relay: { ...valid.relay, allowedFeeRecipients: [] } }, /allowedFeeRecipients/],
    ["a bad fee mode", { ...valid, relay: { ...valid.relay, fee: { mode: "free" } } }, /fee\.mode/],
    ["a user fee without a token", { ...valid, relay: { ...valid.relay, fee: { mode: "sponsored", pool_fee: { paid_by: "user" } } } }, /token/],
    ["a non-object", "nope", /privacy must be an object/],
  ])("rejects %s", (_name, input, message) => {
    expect(() => parseStarknetPrivacyConfig(input)).toThrow(message);
  });
});
