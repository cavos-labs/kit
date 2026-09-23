import { generateMasterDEK } from "./dek";
import { unwrapDek, wrapDek } from "./passkeyWrap";

describe("passkey wrap", () => {
  const prf = new Uint8Array(32).fill(7);
  const owner = { appId: "app-1", userId: "user-1" };

  it("opens with the same passkey and owner", () => {
    const dek = generateMasterDEK();
    expect(unwrapDek(wrapDek(dek, prf, owner), prf, owner)).toEqual(dek);
  });

  it("uses a fresh nonce every time", () => {
    const dek = generateMasterDEK();
    expect(wrapDek(dek, prf, owner)).not.toEqual(wrapDek(dek, prf, owner));
  });

  it("does not open under another passkey", () => {
    const wrap = wrapDek(generateMasterDEK(), prf, owner);
    expect(() => unwrapDek(wrap, new Uint8Array(32).fill(8), owner)).toThrow();
  });

  it("does not open for another user or app", () => {
    const wrap = wrapDek(generateMasterDEK(), prf, owner);
    expect(() => unwrapDek(wrap, prf, { ...owner, userId: "user-2" })).toThrow();
    expect(() => unwrapDek(wrap, prf, { ...owner, appId: "app-2" })).toThrow();
  });

  it("rejects a tampered or unknown wrap", () => {
    const wrap = wrapDek(generateMasterDEK(), prf, owner);
    const tampered = wrap.slice();
    tampered[20] ^= 1;
    expect(() => unwrapDek(tampered, prf, owner)).toThrow();
    const future = wrap.slice();
    future[0] = 2;
    expect(() => unwrapDek(future, prf, owner)).toThrow("unknown passkey wrap format");
    expect(() => unwrapDek(wrap.subarray(1), prf, owner)).toThrow("unknown passkey wrap format");
  });
});
