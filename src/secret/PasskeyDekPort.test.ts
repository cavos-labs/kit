import { LocalDeviceUnwrapKey } from "../chains/stellar/DeviceUnwrapKey";
import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { parseMasterDEK } from "./dek";
import { masterDekFromPasskey, parseAppSalt } from "./derive";
import { deviceFactorFromUnwrapKey } from "./factor";
import { toPasskeyDekPort } from "./PasskeyDekPort";

function mockPasskey(prf: Uint8Array): PasskeyPrfProvider {
  return {
    enroll: async () => ({ credentialId: new Uint8Array(16), secret: prf }),
    getSecret: async () => prf,
  };
}

describe("toPasskeyDekPort", () => {
  const prf = new Uint8Array(32).fill(7);
  const appSalt = parseAppSalt("app-salt");
  const credential = { idToken: "a.b.c", tokenFingerprint: "passkey", provider: "google" as const };

  it("mints the same DEK from the same passkey on a second device", async () => {
    const expected = masterDekFromPasskey(prf, appSalt);
    const first = toPasskeyDekPort({
      passkey: mockPasskey(prf),
      userId: "user-p1",
      appSalt,
    });
    await expect(first.lookupDek({ credential })).resolves.toBeNull();
    await expect(first.enrollDek({ address: "unused", credential, dek: expected })).resolves.toEqual({
      kind: "enrolled",
    });
    const minted = await first.mintDek!({ credential });
    expect(minted).toEqual(expected);

    const factor = deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate());
    const second = toPasskeyDekPort({
      passkey: mockPasskey(prf),
      userId: "user-p1",
      appSalt,
    });
    const wrap = await second.wrapDekToFactor({
      address: "unused",
      credential,
      recipientSec1: factor.publicKeySec1(),
    });
    expect(parseMasterDEK(await factor.unwrap(wrap))).toEqual(expected);
  });

  it("changes the DEK when the app salt changes", async () => {
    const port = toPasskeyDekPort({
      passkey: mockPasskey(prf),
      userId: "user-p2",
      appSalt,
    });
    const other = toPasskeyDekPort({
      passkey: mockPasskey(prf),
      userId: "user-p2",
      appSalt: parseAppSalt("other-app"),
    });
    expect(await port.mintDek!({ credential })).not.toEqual(await other.mintDek!({ credential }));
  });
});
