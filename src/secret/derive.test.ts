import { Keypair } from "@solana/web3.js";
import { Keypair as StellarKeypair } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { parseMasterDEK } from "./dek";
import {
  deriveSeed,
  HKDF_SOLANA,
  masterDekFromPasskey,
  nativeAddress,
  parseAppSalt,
  solanaAddressFromSeed,
  stellarAddressFromSeed,
} from "./derive";

const dek = parseMasterDEK(new Uint8Array(32).fill(0x11));
const salt = parseAppSalt("app-salt");

describe("deriveSeed", () => {
  it("is stable for the same dek, salt, and chain", () => {
    expect(deriveSeed(dek, "solana", salt)).toEqual(deriveSeed(dek, "solana", salt));
    expect(deriveSeed(dek, "stellar", salt)).toEqual(deriveSeed(dek, "stellar", salt));
  });

  it("domain-separates Solana from Stellar", () => {
    expect(deriveSeed(dek, "solana", salt)).not.toEqual(deriveSeed(dek, "stellar", salt));
    expect(HKDF_SOLANA).toBe("cavos-ed25519-solana-v1");
  });

  it("changes when the app salt changes", () => {
    const other = parseAppSalt("other-app");
    expect(deriveSeed(dek, "solana", salt)).not.toEqual(deriveSeed(dek, "solana", other));
  });

  it("hashes a string appSalt to 32 bytes", () => {
    expect(parseAppSalt("app-salt")).toHaveLength(32);
    expect(() => parseAppSalt("")).toThrow("appSalt is empty");
    expect(() => parseAppSalt(new Uint8Array(16))).toThrow("appSalt must be 32 bytes");
  });
});

describe("masterDekFromPasskey", () => {
  const prf = new Uint8Array(32).fill(0x42);

  it("is stable for the same PRF and app salt", () => {
    expect(masterDekFromPasskey(prf, salt)).toEqual(masterDekFromPasskey(prf, salt));
  });

  it("changes when the app salt or PRF changes", () => {
    expect(masterDekFromPasskey(prf, salt)).not.toEqual(
      masterDekFromPasskey(prf, parseAppSalt("other-app")),
    );
    const other = new Uint8Array(32).fill(0x43);
    expect(masterDekFromPasskey(prf, salt)).not.toEqual(masterDekFromPasskey(other, salt));
  });
});

describe("native addresses", () => {
  it("Solana address is the on-curve system-account pubkey of the seed", () => {
    const seed = deriveSeed(dek, "solana", salt);
    const expected = Keypair.fromSeed(Buffer.from(seed)).publicKey.toBase58();
    expect(solanaAddressFromSeed(seed)).toBe(expected);
    expect(nativeAddress(dek, "solana", salt)).toBe(expected);
  });

  it("Stellar address is the G encoding of the seed", () => {
    const seed = deriveSeed(dek, "stellar", salt);
    const expected = StellarKeypair.fromRawEd25519Seed(Buffer.from(seed)).publicKey();
    expect(stellarAddressFromSeed(seed)).toBe(expected);
    expect(nativeAddress(dek, "stellar", salt)).toBe(expected);
  });

  it("Solana and Stellar addresses differ for the same DEK", () => {
    expect(nativeAddress(dek, "solana", salt)).not.toBe(nativeAddress(dek, "stellar", salt));
  });
});
