import { Account, Operation } from "@stellar/stellar-sdk";
import { StellarAdapter } from "./StellarAdapter";
import { generateControlKey } from "./keys";

/** Minimal Horizon stub: only loadAccount is exercised by the builders. */
function stubServer(adapter: StellarAdapter, seq = "100") {
  const fake = { loadAccount: async (addr: string) => new Account(addr, seq) };
  (adapter as unknown as { server: () => unknown }).server = () => fake;
}

/**
 * Device revocation on classic Stellar is a control-key rotation: the tx erases
 * the revoked device's envelope entries and swaps the weight-1 signer. Both
 * halves have to land in ONE transaction — erasing wraps without rotating would
 * revoke nothing (the evicted device may have cached the control seed), and
 * rotating without erasing would leave stale wraps of a dead DEK behind.
 */
describe("StellarAdapter revocation tx building", () => {
  const account = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H";

  it("buildDataTx: deletes entries with a null value and rotates the control signer", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const { keypair: oldControl } = generateControlKey();
    const { keypair: newControl } = generateControlKey();

    const tx = await adapter.buildDataTx({
      account,
      entries: {
        "cv:wd:evicted/0": null,
        "cv:ct/0": Uint8Array.of(1, 2, 3),
      },
      rotation: { newControl: newControl.publicKey(), oldControl: oldControl.publicKey() },
    });

    const data = tx.operations.filter((o) => o.type === "manageData") as Operation.ManageData[];
    const deleted = data.find((o) => o.name === "cv:wd:evicted/0");
    const written = data.find((o) => o.name === "cv:ct/0");
    expect(deleted?.value).toBeNull();
    expect(written?.value).toEqual(Buffer.from([1, 2, 3]));

    // Add the new signer BEFORE dropping the old one — the reverse order would
    // momentarily leave the account unable to meet its own thresholds.
    const setOptions = tx.operations.filter((o) => o.type === "setOptions") as Operation.SetOptions[];
    expect(setOptions).toHaveLength(2);
    expect(setOptions[0].signer).toEqual({ ed25519PublicKey: newControl.publicKey(), weight: 1 });
    expect(setOptions[1].signer).toEqual({ ed25519PublicKey: oldControl.publicKey(), weight: 0 });
  });

  it("buildSponsoredDataTx: rotation ops sit inside the sponsorship window", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const relayer = generateControlKey().keypair.publicKey();
    const { keypair: oldControl } = generateControlKey();
    const { keypair: newControl } = generateControlKey();

    const tx = await adapter.buildSponsoredDataTx({
      relayer,
      account,
      entries: { "cv:ct/0": Uint8Array.of(9) },
      rotation: { newControl: newControl.publicKey(), oldControl: oldControl.publicKey() },
    });

    const types = tx.operations.map((o) => o.type);
    expect(types[0]).toBe("beginSponsoringFutureReserves");
    expect(types[types.length - 1]).toBe("endSponsoringFutureReserves");
    // The new signer is a subentry, so its reserve must be the relayer's.
    const firstSetOptions = types.indexOf("setOptions");
    expect(firstSetOptions).toBeGreaterThan(0);
    expect(firstSetOptions).toBeLessThan(types.length - 1);

    // Every account op is sourced by the account, so the control key signs them.
    for (const op of tx.operations.slice(1)) {
      expect(op.source).toBe(account);
    }
  });

  it("omitting rotation leaves an ordinary data write", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const tx = await adapter.buildDataTx({ account, entries: { "cv:wp/0": Uint8Array.of(1) } });
    expect(tx.operations.every((o) => o.type === "manageData")).toBe(true);
  });
});

/**
 * The relay's `validateSponsoredData` gate is what decides whether a sponsored
 * write is accepted, and it is strict about shape: first/last op sponsorship,
 * everything in between sourced by the account, and setOptions allowed ONLY to
 * change a signer. The revocation transaction is built here but validated
 * there, so these assertions mirror that gate — a build that drifts from it is
 * rejected in production, which is exactly how Stellar revocation shipped
 * broken the first time.
 */
describe("sponsored revocation matches the relay's validation gate", () => {
  const account = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H";

  it("produces begin/end sponsorship, account-sourced ops, signer-only setOptions", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter);
    const relayer = generateControlKey().keypair.publicKey();
    const { keypair: oldControl } = generateControlKey();
    const { keypair: newControl } = generateControlKey();

    const tx = await adapter.buildSponsoredDataTx({
      relayer,
      account,
      entries: { "cv:wd:gone/0": null, "cv:ct/0": Uint8Array.of(7) },
      rotation: { newControl: newControl.publicKey(), oldControl: oldControl.publicKey() },
    });

    const ops = tx.operations;
    expect(ops[0].type).toBe("beginSponsoringFutureReserves");
    expect(ops[ops.length - 1].type).toBe("endSponsoringFutureReserves");
    expect(ops[ops.length - 1].source).toBe(account);

    for (const op of ops.slice(1, -1)) {
      expect(op.source).toBe(account); // the gate rejects any other source
      expect(['manageData', 'setOptions']).toContain(op.type);
      if (op.type === 'manageData') {
        expect(op.name.startsWith('cv:')).toBe(true); // cv: namespace only
      }
      if (op.type === 'setOptions') {
        // Signer edits only — thresholds and master weight must stay untouched,
        // or the relay refuses to sponsor it.
        const so = op as unknown as Record<string, unknown>;
        expect(so.signer).toBeDefined();
        for (const forbidden of [
          'masterWeight', 'lowThreshold', 'medThreshold', 'highThreshold',
          'homeDomain', 'inflationDest', 'clearFlags', 'setFlags',
        ]) {
          // The SDK leaves unset fields as null, so the gate must treat null
          // and undefined alike — it reads either as "not touched".
          expect(so[forbidden] ?? undefined).toBeUndefined();
        }
      }
    }
  });

  it("uses the relayer sequence it is given instead of reading Horizon", async () => {
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    stubServer(adapter, "999");
    const relayer = generateControlKey().keypair.publicKey();

    const tx = await adapter.buildSponsoredDataTx({
      relayer,
      account,
      entries: { "cv:ct/0": Uint8Array.of(1) },
      relayerSequence: "4242",
    });
    // TransactionBuilder consumes the account's sequence, so the tx carries
    // sequence+1 — proving it came from the argument, not the stubbed Horizon.
    expect(tx.sequence).toBe("4243");
  });
});
