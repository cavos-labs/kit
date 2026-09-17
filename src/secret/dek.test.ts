import { generateMasterDEK, parseMasterDEK, zeroize } from "./dek";

describe("MasterDEK", () => {
  it("parses 32 bytes and rejects other lengths", () => {
    const dek = parseMasterDEK(new Uint8Array(32).fill(3));
    expect(dek).toHaveLength(32);
    expect(() => parseMasterDEK(new Uint8Array(31))).toThrow("MasterDEK must be 32 bytes");
    expect(() => parseMasterDEK(new Uint8Array(33))).toThrow("MasterDEK must be 32 bytes");
  });

  it("copies on parse so the caller can zeroize the source", () => {
    const src = new Uint8Array(32).fill(9);
    const dek = parseMasterDEK(src);
    src.fill(0);
    expect(dek[0]).toBe(9);
  });

  it("generateMasterDEK returns 32 random bytes", () => {
    const a = generateMasterDEK();
    const b = generateMasterDEK();
    expect(a).toHaveLength(32);
    expect(a).not.toEqual(b);
  });

  it("zeroize overwrites the buffer", () => {
    const dek = parseMasterDEK(new Uint8Array(32).fill(1));
    zeroize(dek);
    expect(dek.every((b) => b === 0)).toBe(true);
  });
});
