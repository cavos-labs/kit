import { passkeySignerSeed, recoverySignerSeed } from "./derivedSigner";

describe("derivedSigner", () => {
  it("is stable for the same PRF bytes", () => {
    const prf = new Uint8Array(32).fill(7);
    expect(passkeySignerSeed(prf)).toEqual(passkeySignerSeed(prf));
  });

  it("differs from the recovery-code seed", () => {
    const prf = new Uint8Array(32).fill(7);
    expect(passkeySignerSeed(prf)).not.toEqual(recoverySignerSeed("alpha beta gamma"));
  });
});
