import { Account, Operation, xdr } from "@stellar/stellar-sdk";
import { StellarAdapter } from "./StellarAdapter";
import { deriveStellarMasterKeypair, generateControlKey } from "./keys";
import { generateDEK, sealControlSeed } from "./envelope";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import { eciesWrapDEK } from "./envelope";
import type { AccountEnvelope } from "./datamap";

const identity = { userId: "u1", appSalt: "app" };

/** Minimal Horizon stub: only loadAccount is exercised by the builders. */
function stubServer(adapter: StellarAdapter, seq = "100") {
  const fake = { loadAccount: async (addr: string) => new Account(addr, seq) };
  (adapter as unknown as { server: () => unknown }).server = () => fake;
}

describe("StellarAdapter tx building", () => {
  it("buildCreateTx: createAccount + data entries + master-zeroing setOptions", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);

    const master = deriveStellarMasterKeypair(identity);
    const { keypair: control, seed: controlSeed } = generateControlKey();
    const dek = generateDEK();
    const device = LocalDeviceUnwrapKey.generate();
    const envelope: AccountEnvelope = {
      ct: sealControlSeed(controlSeed, dek),
      deviceWraps: { [device.slotId()]: eciesWrapDEK(dek, device.publicKeySec1()) },
    };

    const tx = await adapter.buildCreateTx({
      funder: master.publicKey(), // any funded G in the stub
      masterAddress: master.publicKey(),
      controlAddress: control.publicKey(),
      envelope,
      startingBalance: 20_000_000n,
    });

    const ops = tx.operations;
    expect(ops[0].type).toBe("createAccount");

    const setOptions = ops.find((o) => o.type === "setOptions") as Operation.SetOptions;
    expect(setOptions).toBeDefined();
    expect(setOptions.masterWeight).toBe(0);
    expect(setOptions.lowThreshold).toBe(1);
    expect(setOptions.medThreshold).toBe(1);
    expect(setOptions.highThreshold).toBe(1);
    expect((setOptions.signer as { ed25519PublicKey: string }).ed25519PublicKey).toBe(control.publicKey());

    // Data-entry ops carry the envelope, sourced by the master (so they're
    // authorized while master is still weight 1) and come BEFORE the setOptions.
    const dataOps = ops.filter((o) => o.type === "manageData") as Operation.ManageData[];
    expect(dataOps.length).toBeGreaterThan(0);
    expect(dataOps.every((o) => o.source === master.publicKey())).toBe(true);
    const setOptionsIdx = ops.indexOf(setOptions);
    expect(ops.lastIndexOf(dataOps[dataOps.length - 1])).toBeLessThan(setOptionsIdx);
  });

  it("buildPaymentTx: single native payment sourced by the account", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const g = deriveStellarMasterKeypair(identity).publicKey();

    const tx = await adapter.buildPaymentTx({ from: g, to: g, amount: 5_000_000n });
    expect(tx.operations).toHaveLength(1);
    const pay = tx.operations[0] as Operation.Payment;
    expect(pay.type).toBe("payment");
    expect(pay.amount).toBe("0.5000000");
    expect(tx.source).toBe(g);
  });

  it("wrapFeeBump: relayer becomes the fee source over a control-signed inner tx", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const g = deriveStellarMasterKeypair(identity).publicKey();
    const relayer = generateControlKey().keypair; // any G as fee source

    const inner = await adapter.buildPaymentTx({ from: g, to: g, amount: 1n });
    inner.sign(generateControlKey().keypair);
    const bump = adapter.wrapFeeBump(inner, relayer.publicKey());
    expect(bump.feeSource).toBe(relayer.publicKey());
    expect(bump.innerTransaction.hash().equals(inner.hash())).toBe(true);
  });
});
