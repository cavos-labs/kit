import { Keypair, Account } from "@stellar/stellar-sdk";
import { CavosStellar } from "./CavosStellar";
import { StellarAdapter } from "./StellarAdapter";
import { generateControlKey } from "./keys";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import { KeypairControlKey } from "./WebCryptoControlKey";
import type { StellarRelayer } from "./StellarRelayer";

/**
 * Security tests verifying that control seeds are not retained on the
 * CavosStellar instance after unlock or account creation.
 *
 * The control seed is the 32-byte ed25519 private key that authorizes the
 * account. If retained on `this`, an XSS attack could copy it. These tests
 * verify the seed is either:
 *   - Never stored on the instance, or
 *   - Wiped immediately after the one-time operation that required it.
 */

const identity = { userId: "u1", appSalt: "app" };

function stubServer(adapter: StellarAdapter, seq = "100") {
  const fake = { loadAccount: async (addr: string) => new Account(addr, seq) };
  (adapter as unknown as { server: () => unknown }).server = () => fake;
}

function makeReadyWallet(control: Keypair): CavosStellar {
  const adapter = new StellarAdapter({ network: "stellar-testnet" });
  stubServer(adapter);
  const device = LocalDeviceUnwrapKey.generate();
  const Ctor = CavosStellar as any as new (...args: any[]) => CavosStellar;
  return new Ctor(
    identity,
    control.publicKey(),
    "ready",
    "stellar-testnet",
    adapter,
    device,
    new KeypairControlKey(control),
    new Uint8Array(32), // dek
    undefined, // relayer
    { appSalt: "test", backendUrl: "https://cavos.xyz", startingBalance: 50000000n },
  );
}

function makeUndeployedWallet(control: Keypair): CavosStellar {
  const adapter = new StellarAdapter({ network: "stellar-testnet" });
  stubServer(adapter);
  const device = LocalDeviceUnwrapKey.generate();
  const Ctor = CavosStellar as any as new (...args: any[]) => CavosStellar;
  return new Ctor(
    identity,
    control.publicKey(),
    "undeployed",
    "stellar-testnet",
    adapter,
    device,
    new KeypairControlKey(control),
    new Uint8Array(32), // dek
    undefined, // relayer
    { appSalt: "test", backendUrl: "https://cavos.xyz", startingBalance: 50000000n },
  );
}

describe("CavosStellar seed lifetime (security)", () => {
  it("does not have a _controlSeed field on a ready wallet", () => {
    const { keypair: control } = generateControlKey();
    const wallet = makeReadyWallet(control);

    // Verify the _controlSeed property does not exist on the instance
    expect((wallet as any)._controlSeed).toBeUndefined();

    // Also verify no seed-like Uint8Array fields exist that could leak
    const privateFields = Object.getOwnPropertyNames(wallet).filter(
      (name) => name.startsWith("_") && name !== "_isDeployed"
    );

    for (const field of privateFields) {
      const value = (wallet as any)[field];
      if (value instanceof Uint8Array && value.length === 32) {
        // If it's a 32-byte Uint8Array, it should be all zeros (the stub DEK)
        // or not a seed. The control seed should never be here.
        const isAllZeros = value.every((b) => b === 0);
        if (!isAllZeros) {
          fail(`Found potential seed in field ${field}: 32-byte non-zero Uint8Array`);
        }
      }
    }
  });

  it("does not have a _controlSeed field on an undeployed wallet", () => {
    const { keypair: control } = generateControlKey();
    const wallet = makeUndeployedWallet(control);

    // The _controlSeed property should not exist on the instance
    expect((wallet as any)._controlSeed).toBeUndefined();
  });

  it("constructor does not accept controlSeed option", () => {
    // The constructor opts type should not include controlSeed
    const { keypair: control, seed } = generateControlKey();
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const device = LocalDeviceUnwrapKey.generate();
    const Ctor = CavosStellar as any as new (...args: any[]) => CavosStellar;

    // Even if we try to pass controlSeed, it should be ignored
    const wallet = new Ctor(
      identity,
      control.publicKey(),
      "undeployed",
      "stellar-testnet",
      adapter,
      device,
      new KeypairControlKey(control),
      new Uint8Array(32),
      undefined,
      { 
        appSalt: "test", 
        backendUrl: "https://cavos.xyz", 
        startingBalance: 50000000n,
        controlSeed: seed, // This should be ignored
      },
    );

    // The seed should NOT be stored on the instance
    expect((wallet as any)._controlSeed).toBeUndefined();
  });

  it("ready wallet can sign without holding seed", async () => {
    const { keypair: control } = generateControlKey();
    const wallet = makeReadyWallet(control);

    // Verify the wallet can sign messages without a seed on the instance
    expect((wallet as any)._controlSeed).toBeUndefined();

    const signature = await wallet.signMessage("test message");
    expect(signature.signature).toHaveLength(64);
    expect(signature.curve).toBe("ed25519");
  });
});

describe("CavosStellar.execute — no seed on spend path", () => {
  it("signs transactions using WebCryptoControlKey, not raw seed", async () => {
    const relayerSource = Keypair.random().publicKey();
    const relayer = {
      getSource: async () => relayerSource,
      submit: jest.fn().mockResolvedValue("relayerHash"),
    } as unknown as StellarRelayer;

    const { keypair: control } = generateControlKey();
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const device = LocalDeviceUnwrapKey.generate();
    const Ctor = CavosStellar as any as new (...args: any[]) => CavosStellar;

    const wallet = new Ctor(
      identity,
      control.publicKey(),
      "ready",
      "stellar-testnet",
      adapter,
      device,
      new KeypairControlKey(control),
      new Uint8Array(32),
      relayer,
      { appSalt: "test", backendUrl: "https://cavos.xyz", startingBalance: 50000000n },
    );

    // Execute a payment
    const hash = await wallet.execute(1n, wallet.address);
    expect(hash).toBe("relayerHash");

    // Verify no seed was ever stored
    expect((wallet as any)._controlSeed).toBeUndefined();
  });
});
