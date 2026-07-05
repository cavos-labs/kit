import { randomBytes } from "@noble/hashes/utils";
import {
  generateDEK,
  sealControlSeed,
  openControlSeed,
  wrapDEK,
  unwrapDEK,
  eciesWrapDEK,
  derivePasskeyKEK,
  deriveRecoveryKEK,
} from "./envelope";
import { fromDataEntries, toDataEntries, type AccountEnvelope } from "./datamap";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import { generateControlKey, controlKeypairFromSeed } from "./keys";

/**
 * Factor-parity: every unlock factor (device / passkey / recovery) wraps the SAME
 * DEK, so opening any one must reconstruct the identical control key. Mirrors what
 * `CavosStellar.approveThisDevice*` relies on. (The high-level class itself
 * is exercised against live testnet in scripts/stellar_classic_e2e.ts.)
 */
describe("stellar unlock factors", () => {
  function makeAccount() {
    const { keypair: control, seed: controlSeed } = generateControlKey();
    const dek = generateDEK();
    const device = LocalDeviceUnwrapKey.generate();
    const prf = randomBytes(32);
    const code = "amber basin arch cedar";
    const env: AccountEnvelope = {
      ct: sealControlSeed(controlSeed, dek),
      deviceWraps: { [device.slotId()]: eciesWrapDEK(dek, device.publicKeySec1()) },
      passkeyWrap: wrapDEK(dek, derivePasskeyKEK(prf)),
      recoveryWrap: wrapDEK(dek, deriveRecoveryKEK(code)),
    };
    return { control, dek, device, prf, code, env };
  }

  it("device, passkey and recovery all recover the same control key", async () => {
    const { control, device, prf, code, env } = makeAccount();
    const chain = fromDataEntries(toDataEntries(env)); // through on-chain layout

    const viaDevice = openControlSeed(chain.ct, await device.unwrap(chain.deviceWraps[device.slotId()]));
    const viaPasskey = openControlSeed(chain.ct, unwrapDEK(chain.passkeyWrap!, derivePasskeyKEK(prf)));
    const viaRecovery = openControlSeed(chain.ct, unwrapDEK(chain.recoveryWrap!, deriveRecoveryKEK(code)));

    const target = control.publicKey();
    expect(controlKeypairFromSeed(viaDevice).publicKey()).toBe(target);
    expect(controlKeypairFromSeed(viaPasskey).publicKey()).toBe(target);
    expect(controlKeypairFromSeed(viaRecovery).publicKey()).toBe(target);
  });

  it("approving a new device: unlock via passkey, re-wrap to the new device slot", async () => {
    const { prf, env } = makeAccount();
    const chain = fromDataEntries(toDataEntries(env));

    // New device has no slot yet.
    const newDevice = LocalDeviceUnwrapKey.generate();
    expect(chain.deviceWraps[newDevice.slotId()]).toBeUndefined();

    // Approve: open DEK via passkey, ECIES-wrap it to the new device, append slot.
    const dek = unwrapDEK(chain.passkeyWrap!, derivePasskeyKEK(prf));
    chain.deviceWraps[newDevice.slotId()] = eciesWrapDEK(dek, newDevice.publicKeySec1());

    // Now the new device unlocks silently on its own.
    const persisted = fromDataEntries(toDataEntries(chain));
    const dek2 = await newDevice.unwrap(persisted.deviceWraps[newDevice.slotId()]);
    expect(openControlSeed(persisted.ct, dek2)).toEqual(openControlSeed(chain.ct, dek));
  });

  it("a wrong recovery code cannot open the DEK", () => {
    const { env } = makeAccount();
    expect(() => unwrapDEK(env.recoveryWrap!, deriveRecoveryKEK("wrong words here now"))).toThrow();
  });

  it("a wrong passkey PRF cannot open the DEK", () => {
    const { env } = makeAccount();
    expect(() => unwrapDEK(env.passkeyWrap!, derivePasskeyKEK(randomBytes(32)))).toThrow();
  });
});
