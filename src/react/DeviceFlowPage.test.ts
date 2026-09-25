import { targetsThisDevice } from "./DeviceFlowPage";
import type { CavosWallet } from "../Cavos";

/**
 * The rendering is React plumbing and is not unit-tested here, in line with the
 * rest of `src/react`. What is tested is the one decision that fails silently:
 * whether a revocation request points at the device being used.
 *
 * Getting it wrong in one direction hides a warning the user needs; in the
 * other it blocks a legitimate revocation with a message about the wrong
 * device.
 */

const wallet = (chain: string, x: bigint, y: bigint) =>
  ({ chain, publicKey: { x, y } }) as unknown as CavosWallet;

describe("targetsThisDevice", () => {
  it("recognises the device in use on Starknet, which identifies one by key", () => {
    expect(targetsThisDevice(wallet("starknet", 1n, 2n), { x: 1n, y: 2n })).toBe(true);
  });

  it("does not confuse a different device for this one", () => {
    expect(targetsThisDevice(wallet("starknet", 1n, 2n), { x: 9n, y: 2n })).toBe(false);
    // Both coordinates matter: matching only x would accept a different key.
    expect(targetsThisDevice(wallet("starknet", 1n, 2n), { x: 1n, y: 9n })).toBe(false);
  });

  it("answers no for native Solana, which has no P-256 device key", () => {
    // A native Solana account is a single Ed25519 key derived from the DEK;
    // there is no per-device P-256 signer to compare. This used to pass a
    // hardcoded { x: 0n, y: 0n } to the comparison, so it answered no by
    // accident — for every device, including a real match.
    expect(targetsThisDevice(wallet("solana", 1n, 2n), { x: 1n, y: 2n })).toBe(false);
  });

  it("answers no for Stellar, which has no device key to compare", () => {
    // Stellar classic uses a different account model. Answering no is the safe
    // direction: the SDK still refuses a self-revocation, the user just loses
    // the early warning.
    expect(targetsThisDevice(wallet("stellar", 1n, 2n), { x: 1n, y: 2n })).toBe(false);
  });

  it("answers no before a wallet is connected", () => {
    expect(targetsThisDevice(null, { x: 1n, y: 2n })).toBe(false);
  });
});
