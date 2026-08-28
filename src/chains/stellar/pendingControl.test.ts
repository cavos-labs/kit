import { describe, expect, it, beforeAll } from "@jest/globals";
import "fake-indexeddb/auto";
import { generateControlKey } from "./keys";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import {
  savePendingControl,
  loadPendingControl,
  clearPendingControl,
} from "./pendingControl";

/**
 * The `G…` address IS the control key, so a device that claimed an address in
 * the registry must still hold that exact seed when the first execute creates
 * the account. Until then there is no account to hold the envelope, so it lives
 * locally — and losing it means a wallet nobody can ever create or sign for.
 */
describe("pending control seed", () => {
  let device: LocalDeviceUnwrapKey;

  beforeAll(() => {
    device = LocalDeviceUnwrapKey.generate();
  });

  it("survives a reload: the same device recovers the seed it claimed with", async () => {
    const { seed, keypair } = generateControlKey();
    await savePendingControl(keypair.publicKey(), seed, device);

    const recovered = await loadPendingControl(keypair.publicKey(), device);
    expect(recovered).not.toBeNull();
    expect(Buffer.from(recovered!)).toEqual(Buffer.from(seed));
  });

  it("does not hand the seed to a different device", async () => {
    const { seed, keypair } = generateControlKey();
    await savePendingControl(keypair.publicKey(), seed, device);

    const stranger = LocalDeviceUnwrapKey.generate();
    expect(await loadPendingControl(keypair.publicKey(), stranger)).toBeNull();
  });

  it("returns null for an address this device never claimed", async () => {
    const { keypair } = generateControlKey();
    expect(await loadPendingControl(keypair.publicKey(), device)).toBeNull();
  });

  it("is dropped once the envelope is on-chain", async () => {
    const { seed, keypair } = generateControlKey();
    await savePendingControl(keypair.publicKey(), seed, device);
    await clearPendingControl(keypair.publicKey());
    expect(await loadPendingControl(keypair.publicKey(), device)).toBeNull();
  });
});
