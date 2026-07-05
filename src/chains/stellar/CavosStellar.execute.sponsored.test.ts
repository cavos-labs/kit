import { Account, Keypair } from "@stellar/stellar-sdk";
import { CavosStellar } from "./CavosStellar";
import { StellarAdapter } from "./StellarAdapter";
import { deriveStellarMasterKeypair, generateControlKey } from "./keys";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import type { StellarRelayer } from "./StellarRelayer";

/**
 * Verifies the per-`execute()` `sponsored` flag on `CavosStellar`. The control
 * key signs identically in both modes; only the fee payer differs. With a
 * relayer configured AND `{ sponsored: false }`, the inner tx must be submitted
 * directly (account pays its own fee) — NOT fee-bumped through the relayer.
 *
 * We bypass `connect()` (which hits Horizon to deploy) by constructing the
 * instance via the private constructor with a real adapter + stubbed submission.
 */

const identity = { userId: "u1", appSalt: "app" };

function stubServer(adapter: StellarAdapter, seq = "100") {
  const fake = { loadAccount: async (addr: string) => new Account(addr, seq) };
  (adapter as unknown as { server: () => unknown }).server = () => fake;
}

function makeWallet(opts: { relayer?: StellarRelayer; control: Keypair }): CavosStellar {
  const adapter = new StellarAdapter({ network: "stellar-testnet" });
  stubServer(adapter);
  // Spy on submit at the adapter level so we can assert it was/wasn't called.
  const device = LocalDeviceUnwrapKey.generate();
  const Ctor = CavosStellar as any as new (...args: any[]) => CavosStellar;
  return new Ctor(
    identity,
    deriveStellarMasterKeypair(identity).publicKey(),
    "ready",
    "stellar-testnet",
    adapter,
    device,
    opts.control,
    new Uint8Array(32), // dek — unused on the execute() path
    opts.relayer,
  );
}

describe("CavosStellar.execute — sponsored flag", () => {
  it("fee-bumps through the relayer by default (sponsored: true)", async () => {
    const relayerSource = Keypair.random().publicKey();
    const relayer = {
      getSource: async () => relayerSource,
      submit: jest.fn().mockResolvedValue("relayerHash"),
    } as unknown as StellarRelayer;
    const { keypair: control } = generateControlKey();
    const wallet = makeWallet({ relayer, control });

    const hash = await wallet.execute(1n, wallet.address);
    expect(hash).toBe("relayerHash");
    expect((relayer as any).submit).toHaveBeenCalledWith("fee-bump", expect.any(String));
  });

  it("submits directly when { sponsored: false }", async () => {
    const relayerSource = Keypair.random().publicKey();
    const relayer = {
      getSource: async () => relayerSource,
      submit: jest.fn().mockResolvedValue("relayerHash"),
    } as unknown as StellarRelayer;
    const { keypair: control } = generateControlKey();
    const wallet = makeWallet({ relayer, control });
    const submitSpy = jest
      .spyOn(wallet["adapter"], "submit")
      .mockResolvedValue("selfFundedHash" as never);

    const hash = await wallet.execute(1n, wallet.address, { sponsored: false });
    expect(hash).toBe("selfFundedHash");
    expect(submitSpy).toHaveBeenCalledTimes(1);
    expect((relayer as any).submit).not.toHaveBeenCalled();
  });
});
