import { deriveViewingKey, viewingPublicKey, type ViewingKeyContext } from "./viewingKey";

const CONTEXT: ViewingKeyContext = {
  chainId: "0x534e5f5345504f4c4941",
  accountAddress: "0x1234",
  poolAddress: "0x5678",
};

const VECTORS = [
  {
    id: "primary",
    privateKey: "0x1",
    viewingKey: "0x12eb8ad5ccd790c7f680a4364db37673265f91147173130bed719a511a36bcb",
    publicKeyX: "0x435ada564d3bb1c5ac7caac8aa5fdc7dfa5de1aea83ff660099ea619a08c7a5",
  },
  {
    id: "rejection-sampling",
    privateKey: "0x5",
    viewingKey: "0x1ad67c997ffb3359196403b585305625f57635ce102dff935f1066031289bf0",
    publicKeyX: "0x4366caa68f40c9467a805b2646bcca3ac60c320c165564f69bc2de4b668e7ed",
  },
];

describe("SNIP-44 account-leaf-v1", () => {
  it.each(VECTORS)("matches the $id test vector", ({ privateKey, viewingKey, publicKeyX }) => {
    const derived = deriveViewingKey(privateKey, CONTEXT);
    expect(derived).toBe(viewingKey);
    expect(viewingPublicKey(derived)).toBe(publicKeyX);
  });

  it("binds the key to the chain, account and pool", () => {
    const base = deriveViewingKey("0x1", CONTEXT);
    expect(deriveViewingKey("0x1", { ...CONTEXT, chainId: "0x534e5f4d41494e" })).not.toBe(base);
    expect(deriveViewingKey("0x1", { ...CONTEXT, accountAddress: "0x1235" })).not.toBe(base);
    expect(deriveViewingKey("0x1", { ...CONTEXT, poolAddress: "0x5679" })).not.toBe(base);
  });

  it("reads felts by value, not by spelling", () => {
    expect(deriveViewingKey("0x1", { ...CONTEXT, accountAddress: "0x0000001234" })).toBe(
      deriveViewingKey("0x1", CONTEXT),
    );
  });

  it("refuses a key outside the Stark scalar range", () => {
    expect(() => deriveViewingKey("0x0", CONTEXT)).toThrow("not a Stark scalar");
    expect(() =>
      deriveViewingKey("0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f", CONTEXT),
    ).toThrow("not a Stark scalar");
  });

  it("refuses a context value wider than its field", () => {
    expect(() => deriveViewingKey("0x1", { ...CONTEXT, poolAddress: `0x1${"0".repeat(64)}` })).toThrow(
      "does not fit in 32 bytes",
    );
  });
});
