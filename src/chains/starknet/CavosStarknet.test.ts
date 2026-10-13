import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { Account, RpcProvider, Signer, ec, hash, typedData as snTypedData } from "starknet";
import { LocalDeviceUnwrapKey } from "../stellar/DeviceUnwrapKey";
import { deviceFactorFromUnwrapKey } from "../../secret/factor";
import type { WrapStore } from "../../secret/DeviceSecret";
import type { WrappedDEK } from "../../secret/wrap";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { CavosStarknet } from "./CavosStarknet";
import { OZ_ACCOUNT_CLASS_HASH, STARKNET_NETWORKS } from "./constants";
import { starkKeyFromSeed, starkPublicKey, starknetAddressFromPublicKey } from "./keys";

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const PRIVATE_KEY = starkKeyFromSeed(SEED);
const PUBLIC_KEY = starkPublicKey(PRIVATE_KEY);
const ADDRESS = starknetAddressFromPublicKey(PUBLIC_KEY);
const FULL_PUBLIC_KEY = ec.starkCurve.getPublicKey(PRIVATE_KEY, false);

function build(init: Record<string, unknown>): CavosStarknet {
  const Ctor = CavosStarknet as unknown as new (i: Record<string, unknown>) => CavosStarknet;
  return new Ctor({
    identity: { userId: "u1" },
    address: ADDRESS,
    network: "sepolia",
    status: "undeployed",
    deployed: false,
    provider: { waitForTransaction: jest.fn(async () => ({})) },
    publicKey: PUBLIC_KEY,
    ...init,
  });
}

function mockAccount() {
  return {
    executePaymasterTransaction: jest.fn(async () => ({ transaction_hash: "0xdeploy" })),
    execute: jest.fn(async () => ({ transaction_hash: "0xself" })),
  };
}

describe("CavosStarknet lazy deploy", () => {
  it("sends the OZ deployment data with the first execute and flips to ready", async () => {
    const account = mockAccount();
    const wallet = build({ account });
    const listener = jest.fn();
    wallet.onStatusChange(listener);
    const calls = [{ contractAddress: "0x1", entrypoint: "foo", calldata: ["0x2"] }];

    await expect(wallet.execute(calls)).resolves.toEqual({ transactionHash: "0xdeploy" });

    expect(account.executePaymasterTransaction).toHaveBeenCalledWith(calls, {
      feeMode: { mode: "sponsored" },
      deploymentData: {
        address: ADDRESS,
        class_hash: OZ_ACCOUNT_CLASS_HASH,
        salt: PUBLIC_KEY,
        calldata: [PUBLIC_KEY],
        version: 1,
      },
    });
    expect(wallet.status).toBe("ready");
    expect(wallet.isDeployed).toBe(true);
    expect(wallet.isNewAccount).toBe(true);
    expect(listener).toHaveBeenCalled();
  });

  it("refuses a self-funded first execute", async () => {
    const account = mockAccount();
    const wallet = build({ account });
    await expect(wallet.execute([], { fee: "self" })).rejects.toThrow(/self-funded deploy is not supported/);
    expect(account.executePaymasterTransaction).not.toHaveBeenCalled();
  });

  it("does not deploy again once ready: sponsored by default, own balance on fee self", async () => {
    const account = mockAccount();
    const wallet = build({ account, status: "ready", deployed: true });
    const calls = [{ contractAddress: "0x1", entrypoint: "foo", calldata: [] }];

    await wallet.execute(calls);
    expect(account.executePaymasterTransaction).toHaveBeenCalledWith(calls, { feeMode: { mode: "sponsored" } });

    await expect(wallet.execute(calls, { fee: "self" })).resolves.toEqual({ transactionHash: "0xself" });
    expect(account.execute).toHaveBeenCalledWith(calls);
  });

  it("allows upgrade as a self-call", async () => {
    const account = mockAccount();
    const wallet = build({ account, status: "ready", deployed: true });
    await wallet.upgrade("0xabc");
    expect(account.executePaymasterTransaction).toHaveBeenCalledWith(
      [{ contractAddress: ADDRESS, entrypoint: "upgrade", calldata: ["0xabc"] }],
      { feeMode: { mode: "sponsored" } },
    );
  });
});

describe("CavosStarknet key rotation guard", () => {
  it.each(["set_public_key", "setPublicKey"])("refuses %s on the account itself", async (entrypoint) => {
    const account = mockAccount();
    const wallet = build({ account, status: "ready", deployed: true });
    const call = { contractAddress: ADDRESS, entrypoint, calldata: ["0x1"] };
    await expect(wallet.execute([call])).rejects.toThrow(/rotating the account key is refused/);
    await expect(wallet.signTransaction([call])).rejects.toThrow(/rotating the account key is refused/);
    expect(account.executePaymasterTransaction).not.toHaveBeenCalled();
  });

  it("refuses it when the address is written without zero padding", async () => {
    const wallet = build({ account: mockAccount(), status: "ready", deployed: true });
    const padded = `0x${BigInt(ADDRESS).toString(16).padStart(64, "0")}`;
    await expect(
      wallet.execute([{ contractAddress: padded, entrypoint: "set_public_key", calldata: ["0x1"] }]),
    ).rejects.toThrow(/rotating the account key is refused/);
  });

  it("refuses it when the entrypoint is written as its selector", async () => {
    const wallet = build({ account: mockAccount(), status: "ready", deployed: true });
    const selector = hash.getSelectorFromName("set_public_key");
    await expect(
      wallet.execute([{ contractAddress: ADDRESS, entrypoint: selector, calldata: ["0x1"] }]),
    ).rejects.toThrow(/rotating the account key is refused/);
  });

  it("allows set_public_key on another contract", async () => {
    const account = mockAccount();
    const wallet = build({ account, status: "ready", deployed: true });
    await expect(
      wallet.execute([{ contractAddress: "0x99", entrypoint: "set_public_key", calldata: [] }]),
    ).resolves.toBeDefined();
  });
});

describe("CavosStarknet signMessage", () => {
  const provider = new RpcProvider({ nodeUrl: STARKNET_NETWORKS.sepolia.rpcUrl });
  const wallet = () =>
    build({
      account: new Account({ provider, address: ADDRESS, signer: new Signer(PRIVATE_KEY), cairoVersion: "1" }),
    });

  it("signs SNIP-12 revision 1 typed data that verifies against the account address", async () => {
    const signed = await wallet().signMessage("hello");

    expect(signed.curve).toBe("stark");
    expect(signed.publicKey).toBe(PUBLIC_KEY);
    expect(signed.signature).toHaveLength(64);
    expect(signed.typedData!.primaryType).toBe("Message");
    expect(signed.typedData!.domain).toEqual({
      name: "Cavos",
      version: "1",
      chainId: STARKNET_NETWORKS.sepolia.chainId,
      revision: "1",
    });
    expect(signed.typedData!.message).toEqual({ content: "hello" });

    const messageHash = snTypedData.getMessageHash(signed.typedData!, ADDRESS);
    expect(ec.starkCurve.verify(signed.signature, messageHash, FULL_PUBLIC_KEY)).toBe(true);
  });

  it("encodes bytes as 0x-prefixed hex content", async () => {
    const signed = await wallet().signMessage(new Uint8Array([1, 2, 255]));
    expect(signed.typedData!.message).toEqual({ content: "0x0102ff" });
  });

  it("binds the signature to the network", async () => {
    const signed = await wallet().signMessage("hello");
    const other = { ...signed.typedData!, domain: { ...signed.typedData!.domain, chainId: STARKNET_NETWORKS.mainnet.chainId } };
    const hash = snTypedData.getMessageHash(other, ADDRESS);
    expect(ec.starkCurve.verify(signed.signature, hash, FULL_PUBLIC_KEY)).toBe(false);
  });
});

describe("CavosStarknet.connect", () => {
  afterEach(() => jest.restoreAllMocks());

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

  const connect = (store: WrapStore, registry = new InMemoryWalletRegistry()) =>
    CavosStarknet.connect({
      network: "sepolia",
      identity: { userId: "u-connect" },
      appSalt: "salt",
      registry,
      paymasterApiKey: "key",
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      wrapStore: store,
    });

  it("is undeployed with a key and no class at the address", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockRejectedValue(new Error("Contract not found"));
    const wallet = await connect(new MemoryStore());
    expect(wallet.status).toBe("undeployed");
    expect(wallet.isDeployed).toBe(false);
    expect(wallet.isNewAccount).toBe(true);
    expect(wallet.address).toBe(starknetAddressFromPublicKey(wallet.publicKey));
    await expect(wallet.isReady()).resolves.toBe(true);
  });

  it("is ready with a key and a class at the address", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockResolvedValue(OZ_ACCOUNT_CLASS_HASH);
    const wallet = await connect(new MemoryStore());
    expect(wallet.status).toBe("ready");
    expect(wallet.isDeployed).toBe(true);
  });

  it("needs device approval on a device that holds no key", async () => {
    jest.spyOn(RpcProvider.prototype, "getClassHashAt").mockResolvedValue(OZ_ACCOUNT_CLASS_HASH);
    const registry = new InMemoryWalletRegistry();
    await registry.register({ userId: "u-connect", address: "0x123", initialSigner: { x: 0n, y: 0n } });
    const wallet = await connect(new MemoryStore(), registry);
    expect(wallet.status).toBe("needs-device-approval");
    expect(wallet.address).toBe("0x123");
    await expect(wallet.isReady()).resolves.toBe(false);
    expect(() => wallet.account).toThrow(/holds no key/);
    await expect(wallet.signMessage("x")).rejects.toThrow(/holds no key/);
  });
});
