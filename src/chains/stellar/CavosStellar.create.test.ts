import { Account, Keypair } from "@stellar/stellar-sdk";
import { CavosStellar } from "./CavosStellar";
import { StellarAdapter } from "./StellarAdapter";
import { generateControlKey } from "./keys";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import type { StellarRelayer } from "./StellarRelayer";
import { KeypairControlKey } from "./WebCryptoControlKey";

const identity = { userId: "u1", appSalt: "app" };

function makeWallet(status: "undeployed" | "ready", relayer: StellarRelayer, control: Keypair, exists: boolean) {
  const adapter = new StellarAdapter({ network: "stellar-testnet" });
  const fake = { loadAccount: async (addr: string) => new Account(addr, "100") };
  (adapter as unknown as { server: () => unknown }).server = () => fake;
  jest.spyOn(adapter, "isDeployed").mockResolvedValue(exists);
  const Ctor = CavosStellar as any as new (...args: any[]) => CavosStellar;
  return new Ctor(
    identity,
    control.publicKey(),
    status,
    "stellar-testnet",
    adapter,
    LocalDeviceUnwrapKey.generate(),
    new KeypairControlKey(control),
    new Uint8Array(32),
    relayer,
    { appSalt: "test", backendUrl: "https://cavos.xyz", startingBalance: 50000000n },
  );
}

function makeRelayer() {
  return {
    getSource: async () => Keypair.random().publicKey(),
    submit: jest.fn().mockResolvedValue("createHash"),
  } as unknown as StellarRelayer;
}

describe("CavosStellar.create", () => {
  it("creates an undeployed account through the relayer and becomes ready", async () => {
    const relayer = makeRelayer();
    const { keypair: control } = generateControlKey();
    const wallet = makeWallet("undeployed", relayer, control, false);

    await wallet.create();

    expect((relayer as any).submit).toHaveBeenCalledTimes(1);
    expect((relayer as any).submit).toHaveBeenCalledWith("create", expect.any(String));
    expect(wallet.status).toBe("ready");
    expect(wallet.isDeployed).toBe(true);
  });

  it("does nothing when the account is already ready", async () => {
    const relayer = makeRelayer();
    const { keypair: control } = generateControlKey();
    const wallet = makeWallet("ready", relayer, control, true);

    await wallet.create();

    expect((relayer as any).submit).not.toHaveBeenCalled();
    expect(wallet.status).toBe("ready");
  });

  it("lets addTrustline run right after create", async () => {
    const relayer = makeRelayer();
    const { keypair: control } = generateControlKey();
    const wallet = makeWallet("undeployed", relayer, control, false);

    await expect(
      wallet.addTrustline({ code: "USDC", issuer: Keypair.random().publicKey() }),
    ).rejects.toThrow("Call create() first");

    await wallet.create();
    (relayer as any).submit.mockResolvedValueOnce("trustlineHash");
    const hash = await wallet.addTrustline({ code: "USDC", issuer: Keypair.random().publicKey() });

    expect(hash).toBe("trustlineHash");
    expect((relayer as any).submit).toHaveBeenLastCalledWith("trustline", expect.any(String));
  });
});
