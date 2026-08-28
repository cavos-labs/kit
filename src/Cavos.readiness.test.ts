import { describe, expect, it, jest } from "@jest/globals";
import { Cavos } from "./Cavos";
import type { ConnectStatus } from "./Cavos";

/**
 * Recovery puts this device on-chain as a signer, and the only thing that
 * notices is the poll that asks. If the answer is not recorded, the wallet goes
 * on saying `needs-device-approval` and the execute waiting to be authorized is
 * never told it now can be: it sat out its full 90s timeout after the enclave
 * had already succeeded, then failed claiming the device was not authorized.
 */
describe("polling for readiness records what it finds", () => {
  const pubkey = { x: 1n, y: 2n };

  /** A wallet at some status, over an adapter with a known on-chain answer. */
  const walletAt = (status: ConnectStatus, authorized: boolean) => {
    const isAuthorizedSigner = jest.fn(async () => authorized);
    const wallet = Object.assign(Object.create(Cavos.prototype) as Cavos, {
      statusValue: status,
      statusListeners: new Set<() => void>(),
      adapter: { isAuthorizedSigner },
      address: "0x232e",
      devicePubkey: pubkey,
    });
    return { wallet, isAuthorizedSigner };
  };

  it("turns a device the chain now accepts into a ready wallet", async () => {
    const { wallet } = walletAt("needs-device-approval", true);
    await expect(wallet.isReady()).resolves.toBe(true);
    expect(wallet.status).toBe("ready");
  });

  it("wakes whoever is waiting to be authorized", async () => {
    // The actual repair: the execute that asked for authorization is parked on
    // this notification, and nothing else ever arrives to release it.
    const { wallet } = walletAt("needs-device-approval", true);
    const woken = jest.fn();
    wallet.onStatusChange(woken);

    await wallet.isReady();

    expect(woken).toHaveBeenCalled();
  });

  it("leaves a device the chain still rejects alone", async () => {
    const { wallet } = walletAt("needs-device-approval", false);
    const woken = jest.fn();
    wallet.onStatusChange(woken);

    await expect(wallet.isReady()).resolves.toBe(false);
    expect(wallet.status).toBe("needs-device-approval");
    expect(woken).not.toHaveBeenCalled();
  });

  it("never calls an undeployed account ready", async () => {
    // There is no account yet, so no signer of it either — asking the chain
    // would be meaningless, and answering yes would send a doomed transaction.
    const { wallet, isAuthorizedSigner } = walletAt("undeployed", true);

    await expect(wallet.isReady()).resolves.toBe(false);
    expect(wallet.status).toBe("undeployed");
    expect(isAuthorizedSigner).not.toHaveBeenCalled();
  });
});
