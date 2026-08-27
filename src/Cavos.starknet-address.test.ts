import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { Account, RpcProvider } from "starknet";
import { Cavos } from "./Cavos";
import { appNamespace } from "./identity";
import { StarknetAdapter } from "./chains/starknet/StarknetAdapter";
import type { DeviceSigner } from "./signer/DeviceSigner";
import type { WalletRegistry } from "./registry/WalletRegistry";

describe("Cavos Starknet deterministic address resolution", () => {
  const classHash =
    "0x25cbc5423e8ee895febb0ef2c3945b408da44d0039d915fbdd681fe6b6ba66b";
  const signer: DeviceSigner = {
    getPublicKey: async () => ({ x: 1n, y: 2n }),
    sign: async () => {
      throw new Error("not used");
    },
  };

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("uses the registry's address instead of computing one", async () => {
    jest
      .spyOn(RpcProvider.prototype, "getClassHashAt")
      .mockResolvedValue(classHash);
    jest
      .spyOn(StarknetAdapter.prototype, "isAuthorizedSigner")
      .mockResolvedValue(true);

    const registry: WalletRegistry = {
      lookup: jest.fn(async () => ({ address: "0x123" })),
      register: jest.fn(async () => ({ address: "0x123", conflict: false })),
    };
    const identity = { userId: "google:test-user" };
    const appSalt = "unused-by-address-derivation";

    const wallet = await Cavos.connect({
      chain: "starknet",
      network: "testnet",
      identity,
      appSalt,
      paymasterApiKey: "test-key",
      classHash,
      rpcUrl: "http://127.0.0.1:5050",
      paymasterUrl: "http://127.0.0.1:5051",
      appId: "app-1",
      registry,
      createSigner: async () => signer,
    });

    // The registry is the source of truth: the row wins, and nothing is written.
    expect(wallet.chain).toBe("starknet");
    expect(wallet.address).toBe("0x123");
    expect(registry.lookup).toHaveBeenCalledWith(identity.userId);
    expect(registry.register).not.toHaveBeenCalled();
  });

  it("claims the computed address when the user has none, and adopts the winner on a conflict", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockRejectedValue(new Error("not deployed"));

    const computed = new StarknetAdapter({ classHash }).computeAddress({
      namespace: appNamespace({ appId: "app-1" }),
      initialSigner: { x: 1n, y: 2n },
    });

    const claimed: WalletRegistry = {
      lookup: jest.fn(async () => null),
      register: jest.fn(async () => ({ address: computed, conflict: false })),
    };
    const first = await Cavos.connect({
      chain: "starknet",
      network: "testnet",
      identity: { userId: "google:new-user" },
      appSalt: "unused",
      paymasterApiKey: "test-key",
      classHash,
      rpcUrl: "http://127.0.0.1:5050",
      paymasterUrl: "http://127.0.0.1:5051",
      appId: "app-1",
      registry: claimed,
      createSigner: async () => signer,
    });
    expect(first.address).toBe(computed);
    expect(claimed.register).toHaveBeenCalledWith({
      userId: "google:new-user",
      address: computed,
      initialSigner: { x: 1n, y: 2n },
    });

    // A second device racing for the same identity loses and takes the winner's
    // address rather than the one it computed for itself.
    const lost: WalletRegistry = {
      lookup: jest.fn(async () => null),
      register: jest.fn(async () => ({ address: "0xwinner", conflict: true })),
    };
    const second = await Cavos.connect({
      chain: "starknet",
      network: "testnet",
      identity: { userId: "google:new-user" },
      appSalt: "unused",
      paymasterApiKey: "test-key",
      classHash,
      rpcUrl: "http://127.0.0.1:5050",
      paymasterUrl: "http://127.0.0.1:5051",
      appId: "app-1",
      registry: lost,
      createSigner: async () => signer,
    });
    expect(second.address).toBe("0xwinner");
    expect(second.address).not.toBe(computed);
  });

  it("waits for the recovery schedule receipt before allowing finalize", async () => {
    jest
      .spyOn(RpcProvider.prototype, "getClassHashAt")
      .mockResolvedValue(classHash);
    jest
      .spyOn(StarknetAdapter.prototype, "isAuthorizedSigner")
      .mockResolvedValue(true);
    const waitForTransaction = jest
      .spyOn(Account.prototype, "waitForTransaction")
      .mockResolvedValue({} as never);
    jest.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ result: { transaction_hash: "0xabc" } }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    const registry: WalletRegistry = {
      lookup: jest.fn(async () => null),
      register: jest.fn(async (p: { address: string }) => ({ address: p.address, conflict: false })),
    };
    const wallet = await Cavos.connect({
      chain: "starknet",
      network: "testnet",
      identity: { userId: "google:recovery-user" },
      appSalt: "recovery-salt",
      paymasterApiKey: "test-key",
      classHash,
      rpcUrl: "http://127.0.0.1:5050",
      paymasterUrl: "http://127.0.0.1:5051",
      registry,
      createSigner: async () => signer,
    });
    if (wallet.chain !== "starknet") throw new Error("expected Starknet wallet");

    const result = await wallet.scheduleSocialRecovery({
      nonce: 0n,
      expiresAt: 1_900_000_000n,
      rHex: "0x3",
      sHex: "0x4",
      yParity: false,
    });

    expect(result.transactionHash).toBe("0xabc");
    expect(waitForTransaction).toHaveBeenCalledWith("0xabc");
  });
});
