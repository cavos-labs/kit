import { Account, Operation, xdr } from "@stellar/stellar-sdk";
import { StellarAdapter } from "./StellarAdapter";
import { generateControlKey } from "./keys";
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
  it("buildCreateTx: createAccount + envelope data entries, no signer dance", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);

    const funder = generateControlKey().keypair;
    const { keypair: control, seed: controlSeed } = generateControlKey();
    const dek = generateDEK();
    const device = LocalDeviceUnwrapKey.generate();
    const envelope: AccountEnvelope = {
      ct: sealControlSeed(controlSeed, dek),
      deviceWraps: { [device.slotId()]: eciesWrapDEK(dek, device.publicKeySec1()) },
    };

    const tx = await adapter.buildCreateTx({
      funder: funder.publicKey(),
      controlAddress: control.publicKey(),
      envelope,
      startingBalance: 20_000_000n,
    });

    const ops = tx.operations;
    const create = ops[0] as Operation.CreateAccount;
    expect(create.type).toBe("createAccount");
    // The account created IS the control key — that is what names the wallet.
    expect(create.destination).toBe(control.publicKey());

    // The control key is the account's master key at weight 1, so there is no
    // signer to add and no master to demote.
    expect(ops.some((o) => o.type === "setOptions")).toBe(false);

    const dataOps = ops.filter((o) => o.type === "manageData") as Operation.ManageData[];
    expect(dataOps.length).toBeGreaterThan(0);
    expect(dataOps.every((o) => o.source === control.publicKey())).toBe(true);
  });

  it("buildPaymentTx: single native payment sourced by the account", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const g = generateControlKey().keypair.publicKey();

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
    const g = generateControlKey().keypair.publicKey();
    const relayer = generateControlKey().keypair; // any G as fee source

    const inner = await adapter.buildPaymentTx({ from: g, to: g, amount: 1n });
    inner.sign(generateControlKey().keypair);
    const bump = adapter.wrapFeeBump(inner, relayer.publicKey());
    expect(bump.feeSource).toBe(relayer.publicKey());
    expect(bump.innerTransaction.hash().equals(inner.hash())).toBe(true);
  });
});
