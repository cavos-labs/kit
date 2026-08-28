import { describe, expect, it } from "@jest/globals";
import { assertDeviceApprovalScope } from "./deviceApprovalScope";

/**
 * A multichain app on passkeys has chains where a new device cannot be
 * authorized at all — not degraded, stuck. The passkey is registered per chain,
 * and keeping one credential in step across accounts created at different times
 * is where the machinery came from that this replaces.
 */
describe("passkey approval is a single-chain choice", () => {
  it("refuses a multichain app", () => {
    expect(() => assertDeviceApprovalScope("passkey", ["starknet", "solana", "stellar"])).toThrow(
      /supports one chain/,
    );
  });

  it("names the chains, so the fix is obvious", () => {
    // Read in a console during integration, not in a bug report from a user
    // who cannot sign.
    expect(() => assertDeviceApprovalScope("passkey", ["starknet", "solana"])).toThrow(
      /starknet, solana/,
    );
  });

  it("allows a single-chain app", () => {
    expect(() => assertDeviceApprovalScope("passkey", ["stellar"])).not.toThrow();
  });

  it("leaves the enclave alone at any number of chains", () => {
    // It mints an authority per wallet, so one login covers all of them and
    // there is nothing to keep in step.
    expect(() =>
      assertDeviceApprovalScope("enclave", ["starknet", "solana", "stellar"]),
    ).not.toThrow();
  });
});
