import { getStarkKey, grindKey } from "@scure/starknet";
import { CallData, hash, num } from "starknet";
import { OZ_ACCOUNT_CLASS_HASH } from "./constants";
import {
  starkKeyFromSeed,
  starkPublicKey,
  starknetAddressFromPublicKey,
  starknetAddressFromSeed,
} from "./keys";

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

const PRIVATE_KEY = "0x15eda6d1c5d63ed2dbb5930b50d7ae1142a9996f8a1dc6c69c45faa1947e0fa";
const PUBLIC_KEY = "0x3c872c760579c4809341a87cd85cd8213f42ddff9d383c7807d61f3d8066be8";
const ADDRESS = "0x3d18ba7867af4b403d0ea3ccd317e3177678af3d5bb4cd95606fa13401cf991";

describe("stark key derivation", () => {
  it("grinds the private key and derives the public key as @scure/starknet does", () => {
    const privateKey = `0x${grindKey(SEED)}`;
    expect(starkKeyFromSeed(SEED)).toBe(privateKey);
    expect(starkPublicKey(privateKey)).toBe(getStarkKey(privateKey));
  });

  it("matches the pinned vector", () => {
    expect(starkKeyFromSeed(SEED)).toBe(PRIVATE_KEY);
    expect(starkPublicKey(PRIVATE_KEY)).toBe(PUBLIC_KEY);
    expect(starknetAddressFromSeed(SEED)).toBe(ADDRESS);
  });

  it("is deterministic and changes with the seed", () => {
    expect(starkKeyFromSeed(SEED)).toBe(starkKeyFromSeed(SEED));
    expect(starkKeyFromSeed(new Uint8Array(32).fill(9))).not.toBe(PRIVATE_KEY);
  });
});

describe("starknet address", () => {
  it("follows the OpenZeppelin convention from the starknet.js guide", () => {
    const expected = hash.calculateContractAddressFromHash(
      PUBLIC_KEY,
      OZ_ACCOUNT_CLASS_HASH,
      CallData.compile({ publicKey: PUBLIC_KEY }),
      0,
    );
    expect(starknetAddressFromPublicKey(PUBLIC_KEY)).toBe(expected);
    expect(starknetAddressFromSeed(SEED)).toBe(expected);
  });

  it("is the unpadded lowercase hex the registry stores", () => {
    const address = starknetAddressFromSeed(SEED);
    expect(address).toMatch(/^0x[1-9a-f][0-9a-f]*$/);
    expect(address).toBe(num.toHex(BigInt(address)));
  });

  it("pins the OZ AccountUpgradeable class hash", () => {
    expect(OZ_ACCOUNT_CLASS_HASH).toBe(
      "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381",
    );
  });
});
