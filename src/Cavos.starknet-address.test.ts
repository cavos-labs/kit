import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { Account, RpcProvider } from "starknet";
import { Cavos } from "./Cavos";
import { deriveAddressSeed } from "./identity";
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

  it("ignores a stale registry address and derives from userId + appSalt", async () => {
    jest
      .spyOn(RpcProvider.prototype, "getClassHashAt")
      .mockResolvedValue(classHash);
    jest
      .spyOn(StarknetAdapter.prototype, "isAuthorizedSigner")
      .mockResolvedValue(true);

    const registry: WalletRegistry = {
      lookup: jest.fn(async () => ({ address: "0x123" })),
      register: jest.fn(async () => undefined),
    };
    const identity = { userId: "google:test-user" };
    const appSalt = "rotated-app-salt";

    const wallet = await Cavos.connect({
      chain: "starknet",
      network: "testnet",
      identity,
      appSalt,
      paymasterApiKey: "test-key",
      classHash,
      rpcUrl: "http://127.0.0.1:5050",
      paymasterUrl: "http://127.0.0.1:5051",
      registry,
      createSigner: async () => signer,
    });

    const expected = new StarknetAdapter({ classHash }).computeAddress({
      addressSeed: deriveAddressSeed({ userId: identity.userId, appSalt }),
    });

    expect(wallet.chain).toBe("starknet");
    expect(wallet.address).toBe(expected);
    expect(wallet.address).not.toBe("0x123");
    expect(registry.lookup).not.toHaveBeenCalled();
    expect(registry.register).toHaveBeenCalledWith({
      userId: identity.userId,
      address: expected,
      initialSigner: { x: 1n, y: 2n },
    });
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
      register: jest.fn(async () => undefined),
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
