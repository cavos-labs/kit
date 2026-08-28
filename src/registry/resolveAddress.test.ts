import { describe, expect, it, jest } from "@jest/globals";
import { resolveAddress } from "./resolveAddress";
import type { WalletRegistry } from "./WalletRegistry";
import type { DevicePublicKey } from "../signer/DeviceSigner";

const key = { userId: "google:u1", appId: "app-1", chain: "starknet", network: "sepolia" };
const device: DevicePublicKey = { x: 1n, y: 2n };

function registryOf(over: Partial<WalletRegistry>): WalletRegistry {
  return {
    lookup: jest.fn(async () => null),
    register: jest.fn(async (p: { address: string }) => ({ address: p.address, conflict: false })),
    ...over,
  } as WalletRegistry;
}

describe("resolveAddress", () => {
  it("prefers the registry over computing an address", async () => {
    const compute = jest.fn(() => "0xcomputed");
    const registry = registryOf({ lookup: jest.fn(async () => ({ address: "0xregistry" })) });

    const result = await resolveAddress({ key, registry, initialSigner: device, compute });

    expect(result).toEqual({ address: "0xregistry", existing: true });
    expect(compute).not.toHaveBeenCalled();
    expect(registry.register).not.toHaveBeenCalled();
  });

  it("claims the computed address when the user has none", async () => {
    const registry = registryOf({});
    const result = await resolveAddress({
      key,
      registry,
      initialSigner: device,
      compute: () => "0xmine",
    });

    expect(result).toEqual({ address: "0xmine", existing: false });
    expect(registry.register).toHaveBeenCalledWith({
      userId: key.userId,
      address: "0xmine",
      initialSigner: device,
    });
  });

  it("adopts the winner's address when another device claimed first", async () => {
    const registry = registryOf({
      register: jest.fn(async () => ({ address: "0xwinner", conflict: true })),
    });

    const result = await resolveAddress({
      key,
      registry,
      initialSigner: device,
      compute: () => "0xmine",
    });

    expect(result).toEqual({ address: "0xwinner", existing: true });
  });

  it("fails rather than minting a second wallet when the registry is unreachable", async () => {
    const registry = registryOf({
      lookup: jest.fn(async () => {
        throw new Error("network down");
      }),
    });

    await expect(
      resolveAddress({ key, registry, initialSigner: device, compute: () => "0xmine" }),
    ).rejects.toThrow("network down");
  });

  it("reports a lost race as existing, so callers discard what they computed", async () => {
    // Stellar generates its control key inside `compute`. If a conflict were
    // reported as `existing: false`, that losing key would be persisted under
    // the winner's address and the device would think it owned the wallet.
    const registry = registryOf({
      register: jest.fn(async () => ({ address: "0xwinner", conflict: true })),
    });
    const { address, existing } = await resolveAddress({
      key,
      registry,
      initialSigner: device,
      compute: () => "0xmine",
    });
    expect(existing).toBe(true);
    expect(address).toBe("0xwinner");
  });

  it("computes locally when there is no registry (no appId)", async () => {
    const result = await resolveAddress({
      key,
      registry: null,
      initialSigner: device,
      compute: () => "0xlocal",
    });
    expect(result).toEqual({ address: "0xlocal", existing: false });
  });
});
