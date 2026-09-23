import { hash } from "starknet";
import { isQueryVersion, parseStarknetCalls, parseStarknetTypedData } from "./parseStarknet";
import { outsideExecution } from "./fixtures";

const ACCOUNT = "0x0123";
const ETH = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
const USDC = "0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb";
const RECIPIENT = "0x0abc";
const TRANSFER = hash.getSelectorFromName("transfer");

describe("parseStarknetCalls", () => {
  it("reads an ETH transfer as a spend in wei", () => {
    const parsed = parseStarknetCalls([{ to: ETH, selector: TRANSFER, calldata: [RECIPIENT, "0x2386f26fc10000", "0x0"] }], ACCOUNT);
    expect(parsed.spends).toEqual([{ asset: "ETH", amount: 10_000_000_000_000_000n, decimals: 18 }]);
    expect(parsed.lines).toEqual([{ kind: "send", amount: "0.01", asset: "ETH", to: `0x${"0".repeat(61)}abc` }]);
    expect(parsed.flagged).toBe(false);
  });

  it("uses the token's own decimals", () => {
    const parsed = parseStarknetCalls([{ to: USDC, selector: TRANSFER, calldata: [RECIPIENT, "0x1312d00", "0x0"] }], ACCOUNT);
    expect(parsed.lines[0]).toMatchObject({ amount: "20", asset: "USDC" });
  });

  it("flags calls into the account itself", () => {
    const addSigner = hash.getSelectorFromName("add_signer");
    expect(parseStarknetCalls([{ to: "0x123", selector: addSigner, calldata: [] }], ACCOUNT).flagged).toBe(true);
  });

  it("flags approvals and unknown contracts", () => {
    const approve = hash.getSelectorFromName("approve");
    expect(parseStarknetCalls([{ to: ETH, selector: approve, calldata: [RECIPIENT, "0x1", "0x0"] }], ACCOUNT).flagged).toBe(true);
    expect(parseStarknetCalls([{ to: "0x999", selector: TRANSFER, calldata: [RECIPIENT, "0x1", "0x0"] }], ACCOUNT).flagged).toBe(true);
  });
});

describe("parseStarknetTypedData", () => {
  it("reads the calls of a SNIP-9 outside execution", () => {
    const parsed = parseStarknetTypedData(
      outsideExecution([{ To: ETH, Selector: TRANSFER, Calldata: [RECIPIENT, "0x2386f26fc10000", "0x0"] }]),
      ACCOUNT,
    );
    expect(parsed.spends).toEqual([{ asset: "ETH", amount: 10_000_000_000_000_000n, decimals: 18 }]);
  });

  it("flags any other typed data", () => {
    const other = { ...outsideExecution([]), primaryType: "Mail" };
    expect(parseStarknetTypedData(other, ACCOUNT).flagged).toBe(true);
  });
});

describe("isQueryVersion", () => {
  it("recognises fee-estimate versions only", () => {
    expect(isQueryVersion("0x100000000000000000000000000000003")).toBe(true);
    expect(isQueryVersion("0x3")).toBe(false);
  });
});
