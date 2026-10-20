import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { RpcProvider } from "starknet";
import { LocalDeviceUnwrapKey } from "../stellar/DeviceUnwrapKey";
import { deviceFactorFromUnwrapKey } from "../../secret/factor";
import type { WrapStore } from "../../secret/DeviceSecret";
import type { WrappedDEK } from "../../secret/wrap";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import type { VaultClient } from "../../vault/VaultClient";
import { CavosStarknet } from "./CavosStarknet";
import { STARKNET_NETWORKS } from "./constants";
import * as session from "./privacy/session";
import type { PrivacyOperations } from "./privacy/session";
import type { StarknetPrivacyConfig } from "./privacy/config";

class MemoryStore implements WrapStore {
  private rows = new Map<string, WrappedDEK>();
  async get(userId: string) {
    return this.rows.get(userId) ?? null;
  }
  async put(userId: string, wrap: WrappedDEK) {
    this.rows.set(userId, wrap);
  }
  async clear(userId: string) {
    this.rows.delete(userId);
  }
}

const privacy: StarknetPrivacyConfig = {
  pool: "0x123",
  prover: "https://prover.example.com",
  discovery: "https://discovery.example.com",
  relay: {
    url: "https://relay.example.com",
    fee: { mode: "sponsored", pool_fee: { paid_by: "sponsor" } },
    maxFee: "1000",
    allowedFeeRecipients: ["0x75a1"],
  },
};

const connect = (extra: Record<string, unknown> = {}) =>
  CavosStarknet.connect({
    network: "sepolia",
    identity: { userId: "u-privacy" },
    appSalt: "salt",
    registry: new InMemoryWalletRegistry(),
    paymasterApiKey: "page-key",
    factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
    wrapStore: new MemoryStore(),
    ...extra,
  });

describe("CavosStarknet.privacy", () => {
  afterEach(() => jest.restoreAllMocks());

  it("runs the session locally with the connect options when the key is in the page", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockRejectedValue(new Error("Contract not found"));
    const operations: PrivacyOperations = {
      status: jest.fn(async () => ({ registered: true })),
      balance: jest.fn(async () => 7n),
      register: jest.fn(async () => ({ transactionHash: "0x1" })),
      deposit: jest.fn(async () => ({ transactionHash: "0x2" })),
      transfer: jest.fn(async () => ({ transactionHash: "0x3" })),
      withdraw: jest.fn(async () => ({ transactionHash: "0x4" })),
    };
    const create = jest.spyOn(session, "createPrivacySession").mockReturnValue(operations as session.PrivacySession);

    const wallet = await connect({ privacy });

    const init = create.mock.calls[0]![0];
    expect(init.config.pool).toBe("0x123");
    expect(init.chainId).toBe(STARKNET_NETWORKS.sepolia.chainId);
    expect(init.account.address).toBe(wallet.address);
    expect(init.paymasterApiKey()).toBe("page-key");
    expect(await wallet.privacy.balance("0x1")).toBe(7n);
    expect(await wallet.privacy.deposit("0x1", 5n)).toEqual({ transactionHash: "0x2" });
  });

  it("says what is missing when the page gives no settings", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockRejectedValue(new Error("Contract not found"));
    const wallet = await connect();
    await expect(wallet.privacy.status()).rejects.toThrow(/`privacy` in the connect options/);
    await expect(wallet.privacy.transfer("0x1", "0x2", 1n)).rejects.toThrow(/`privacy` in the connect options/);
  });

  it("validates the settings when connecting", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockRejectedValue(new Error("Contract not found"));
    await expect(connect({ privacy: { ...privacy, pool: "nope" } })).rejects.toThrow(/privacy\.pool/);
  });

  it("refuses page settings when the key is in the vault", async () => {
    const vault = { connectStarknet: jest.fn() } as unknown as VaultClient;
    await expect(connect({ vault, privacy })).rejects.toThrow(/Cavos dashboard/);
    expect(vault.connectStarknet).not.toHaveBeenCalled();
  });

  it("uses the vault's operations and hands it the paymaster key", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockRejectedValue(new Error("Contract not found"));
    const operations = { status: jest.fn(async () => ({ registered: false })) } as unknown as PrivacyOperations;
    const connectStarknet = jest.fn(async () => ({
      address: "0xabc",
      isNewAccount: false,
      signer: null,
      passkey: false,
      privacy: operations,
    }));
    const wallet = await connect({ vault: { connectStarknet } as unknown as VaultClient, factor: undefined, wrapStore: undefined });
    expect(connectStarknet.mock.calls[0]![1]).toBe("page-key");
    expect(await wallet.privacy.status()).toEqual({ registered: false });
  });
});
