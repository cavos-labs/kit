import { resolveFeeMode } from "./ChainAdapter";

/**
 * `fee` lived in the shared options while only Solana read it, so a
 * `{ fee: 'self' }` written against Stellar or Starknet was silently ignored
 * and the transaction went out sponsored. All three resolve through here now.
 */
describe("resolveFeeMode", () => {
  it("returns the fallback when nothing is asked for", () => {
    expect(resolveFeeMode(undefined, "sponsored")).toBe("sponsored");
    expect(resolveFeeMode({}, "self")).toBe("self");
  });

  it("honours fee over the fallback", () => {
    expect(resolveFeeMode({ fee: "self" }, "sponsored")).toBe("self");
    expect(resolveFeeMode({ fee: "sponsored" }, "self")).toBe("sponsored");
  });

  it("carries a token through untouched", () => {
    expect(resolveFeeMode({ fee: { token: "USDC" } }, "self")).toEqual({ token: "USDC" });
  });

  it("still reads the deprecated sponsored flag", () => {
    expect(resolveFeeMode({ sponsored: true }, "self")).toBe("sponsored");
    expect(resolveFeeMode({ sponsored: false }, "sponsored")).toBe("self");
  });

  it("lets fee win over a contradicting sponsored", () => {
    expect(resolveFeeMode({ fee: "self", sponsored: true }, "sponsored")).toBe("self");
    expect(resolveFeeMode({ fee: "sponsored", sponsored: false }, "self")).toBe("sponsored");
  });

  it("treats each chain's own default as the fallback", () => {
    // Solana: a system account is signer and fee payer at once.
    expect(resolveFeeMode(undefined, "self")).toBe("self");
    // Starknet and Stellar: a fresh account cannot bootstrap itself.
    expect(resolveFeeMode(undefined, "sponsored")).toBe("sponsored");
  });
});
