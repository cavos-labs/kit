import { randomBytes } from "@noble/hashes/utils";
import {
  generateDEK,
  sealControlSeed,
  openControlSeed,
  wrapDEK,
  unwrapDEK,
  derivePasskeyKEK,
  eciesWrapDEK,
  DATA_ENTRY_MAX,
} from "./envelope";
import { toDataEntries, fromDataEntries, deviceWrapEntries, VERSION_KEY, type AccountEnvelope } from "./datamap";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import { generateControlKey, controlKeypairFromSeed } from "./keys";

describe("stellar datamap", () => {
  it("round-trips an envelope through data entries", () => {
    const env: AccountEnvelope = {
      ct: randomBytes(60),
      deviceWraps: { aabbccdd: randomBytes(93), "11223344": randomBytes(93) },
      passkeyWrap: randomBytes(60),
      recoveryWrap: randomBytes(60),
    };
    const entries = toDataEntries(env);
    const back = fromDataEntries(entries);
    expect(back.ct).toEqual(env.ct);
    expect(back.deviceWraps).toEqual(env.deviceWraps);
    expect(back.passkeyWrap).toEqual(env.passkeyWrap);
    expect(back.recoveryWrap).toEqual(env.recoveryWrap);
  });

  it("keeps every data-entry value within the 64-byte limit", () => {
    const env: AccountEnvelope = { ct: randomBytes(60), deviceWraps: { aabbccdd: randomBytes(93) } };
    for (const value of Object.values(toDataEntries(env))) {
      expect(value.length).toBeLessThanOrEqual(DATA_ENTRY_MAX);
    }
  });

  it("omits optional wraps when absent", () => {
    const entries = toDataEntries({ ct: randomBytes(60), deviceWraps: {} });
    expect(Object.keys(entries).some((k) => k.startsWith("cv:wp"))).toBe(false);
    expect(Object.keys(entries).some((k) => k.startsWith("cv:wr"))).toBe(false);
    expect(entries[VERSION_KEY]).toBeDefined();
  });

  it("enumerates device slots from data-entry keys alone", () => {
    const env: AccountEnvelope = {
      ct: randomBytes(60),
      deviceWraps: { slotone1: randomBytes(93), slottwo2: randomBytes(40) },
    };
    const back = fromDataEntries(toDataEntries(env));
    expect(Object.keys(back.deviceWraps).sort()).toEqual(["slotone1", "slottwo2"]);
  });

  it("throws when the control ciphertext is missing", () => {
    expect(() => fromDataEntries({ "cv:v": Uint8Array.of(1) })).toThrow(/cv:ct/);
  });

  it("full lifecycle: seal → device-wrap → on-chain layout → unlock control keypair", async () => {
    // Account creation: random control key, DEK-sealed, wrapped to this device.
    const { keypair: control, seed: controlSeed } = generateControlKey();
    const dek = generateDEK();
    const device = LocalDeviceUnwrapKey.generate();

    const env: AccountEnvelope = {
      ct: sealControlSeed(controlSeed, dek),
      deviceWraps: { [device.slotId()]: eciesWrapDEK(dek, device.publicKeySec1()) },
    };

    // Persist to (and reload from) the on-chain data-entry layout.
    const reloaded = fromDataEntries(toDataEntries(env));

    // Daily unlock, from only { on-chain envelope, device key }:
    const dek2 = await device.unwrap(reloaded.deviceWraps[device.slotId()]);
    const recoveredSeed = openControlSeed(reloaded.ct, dek2);
    expect(controlKeypairFromSeed(recoveredSeed).publicKey()).toBe(control.publicKey());
  });

  it("adds a second factor without touching the control ciphertext", () => {
    const { seed: controlSeed } = generateControlKey();
    const dek = generateDEK();
    const device = LocalDeviceUnwrapKey.generate();
    const ct = sealControlSeed(controlSeed, dek);

    // A passkey approves later: wrap the SAME dek under the passkey KEK. The
    // control ciphertext is unchanged; only a new wrap slot is added.
    const prf = randomBytes(32);
    const env: AccountEnvelope = {
      ct,
      deviceWraps: { [device.slotId()]: eciesWrapDEK(dek, device.publicKeySec1()) },
      passkeyWrap: wrapDEK(dek, derivePasskeyKEK(prf)),
    };
    const back = fromDataEntries(toDataEntries(env));
    expect(back.ct).toEqual(ct);
    expect(unwrapDEK(back.passkeyWrap!, derivePasskeyKEK(prf))).toEqual(dek);
  });

  it("deviceWrapEntries writes only that device's slot", () => {
    const device = LocalDeviceUnwrapKey.generate();
    const entries = deviceWrapEntries(device.slotId(), randomBytes(93));
    expect(Object.keys(entries).every((k) => k.startsWith(`cv:wd:${device.slotId()}/`))).toBe(true);
  });
});
