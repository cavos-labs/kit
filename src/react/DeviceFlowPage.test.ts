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
  it("recognises the device in use on the chains that identify one by key", () => {
    expect(targetsThisDevice(wallet("starknet", 1n, 2n), { x: 1n, y: 2n })).toBe(true);
    expect(targetsThisDevice(wallet("solana", 1n, 2n), { x: 1n, y: 2n })).toBe(true);
  });

  it("does not confuse a different device for this one", () => {
    expect(targetsThisDevice(wallet("starknet", 1n, 2n), { x: 9n, y: 2n })).toBe(false);
    // Both coordinates matter: matching only x would accept a different key.
    expect(targetsThisDevice(wallet("starknet", 1n, 2n), { x: 1n, y: 9n })).toBe(false);
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
