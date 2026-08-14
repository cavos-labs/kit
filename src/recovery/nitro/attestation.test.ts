import { verifyNitroAttestation, isAcceptedMeasurement } from "./attestation";
import { REAL_ATTESTATION_B64, REAL_ATTESTATION_TIMESTAMP } from "./fixtures/realAttestation";

/**
 * These tests run against a genuine AWS-signed attestation document.
 *
 * That is the whole point. A verifier exercised only against documents we
 * generated ourselves proves that the code agrees with itself, not that it
 * agrees with AWS — and the wire format has already surprised us once: real
 * documents encode the payload as an indefinite-length CBOR map, which a
 * reasonable-looking strict decoder rejects.
 */

const REAL_PCR0 =
  "4b8d4cf2a99e05ce1b5bddaf9d21cb446eb0e606c5bebd1ebf02b473a22165f7b68b0bb0d1ac5a90f0311e493522cfab";

const now = new Date(REAL_ATTESTATION_TIMESTAMP);
const policy = { pcr0: REAL_PCR0 };

function realDocument(): Uint8Array {
  return Uint8Array.from(Buffer.from(REAL_ATTESTATION_B64, "base64"));
}

/** The COSE payload sits after `84 44 <4 bytes> a0 59 <2-byte length>`. */
const PAYLOAD_OFFSET = 10;

function tamper(offset: number): Uint8Array {
  const bytes = realDocument();
  bytes[offset] ^= 0x01;
  return bytes;
}

describe("verifyNitroAttestation", () => {
  it("accepts a real AWS-signed document and returns its contents", async () => {
    const attestation = await verifyNitroAttestation(realDocument(), policy, { now });

    expect(attestation.moduleId).toBe("i-0368fa67e156d6d23-enc019b8596b1a9dad6");
    expect(attestation.timestamp.getTime()).toBe(REAL_ATTESTATION_TIMESTAMP);
    expect(Buffer.from(attestation.pcrs.get(0)!).toString("hex")).toBe(REAL_PCR0);
    expect(attestation.pcrs.size).toBe(16);
    // This document carries user_data but no public_key or nonce; absent
    // optional fields are encoded as CBOR null and must read back as undefined.
    expect(attestation.userData).toHaveLength(20);
    expect(attestation.publicKey).toBeUndefined();
    expect(attestation.nonce).toBeUndefined();
  });

  it("accepts a policy that lists several measurements, for overlapping rollouts", async () => {
    const attestation = await verifyNitroAttestation(
      realDocument(),
      { pcr0: ["00".repeat(48), REAL_PCR0] },
      { now },
    );
    expect(attestation.moduleId).toContain("-enc");
  });

  it("rejects an enclave image the policy does not list", async () => {
    await expect(
      verifyNitroAttestation(realDocument(), { pcr0: "00".repeat(48) }, { now }),
    ).rejects.toThrow(/image measurement is not accepted/);
  });

  it("fails closed when the policy lists no measurement at all", async () => {
    await expect(
      verifyNitroAttestation(realDocument(), { pcr0: [] }, { now }),
    ).rejects.toThrow(/image measurement is not accepted/);
  });

  it("rejects a tampered payload", async () => {
    // Flip a bit inside module_id, well clear of the certificate bytes, so the
    // chain still validates and the COSE signature is what catches it.
    await expect(
      verifyNitroAttestation(tamper(PAYLOAD_OFFSET + 20), policy, { now }),
    ).rejects.toThrow();
  });

  it("rejects a tampered signature", async () => {
    const bytes = realDocument();
    await expect(
      verifyNitroAttestation(tamper(bytes.length - 1), policy, { now }),
    ).rejects.toThrow(/signature is invalid/);
  });

  it("rejects a tampered certificate chain", async () => {
    // Byte 2000 lands inside the DER of the leaf certificate.
    await expect(verifyNitroAttestation(tamper(2000), policy, { now })).rejects.toThrow();
  });

  it("rejects a document that is too old to be a live session", async () => {
    const stale = new Date(REAL_ATTESTATION_TIMESTAMP + 6 * 60_000);
    await expect(verifyNitroAttestation(realDocument(), policy, { now: stale })).rejects.toThrow(
      /stale/,
    );
  });

  it("rejects a document when the client's clock is rewound", async () => {
    // The enclave's leaf certificate is minted 42 seconds before the document,
    // so on a genuine AWS document the certificate window catches a rewound
    // clock before the future-dating check ever runs. Both are real defences;
    // this asserts the rejection, not which one fired.
    const rewound = new Date(REAL_ATTESTATION_TIMESTAMP - 6 * 60_000);
    await expect(
      verifyNitroAttestation(realDocument(), policy, { now: rewound }),
    ).rejects.toThrow();
  });

  it("rejects a document whose certificates are outside their validity window", async () => {
    // A year later the measurement and signature are still fine; only the
    // certificate chain has expired. Staleness is checked after the chain, so
    // this exercises the validity-window check specifically.
    const muchLater = new Date(REAL_ATTESTATION_TIMESTAMP + 365 * 24 * 3600_000);
    await expect(
      verifyNitroAttestation(realDocument(), policy, { now: muchLater }),
    ).rejects.toThrow(/validity window/);
  });

  it("rejects a truncated document", async () => {
    await expect(
      verifyNitroAttestation(realDocument().subarray(0, 2000), policy, { now }),
    ).rejects.toThrow();
  });
});

describe("isAcceptedMeasurement", () => {
  it("matches regardless of 0x prefix or case", () => {
    expect(isAcceptedMeasurement("AABB", ["0xaabb"])).toBe(true);
    expect(isAcceptedMeasurement("0xaabb", "AABB")).toBe(true);
  });

  it("never matches an empty or missing measurement", () => {
    expect(isAcceptedMeasurement(undefined, ["aabb"])).toBe(false);
    expect(isAcceptedMeasurement("", ["aabb"])).toBe(false);
  });

  it("never matches an empty accepted list", () => {
    expect(isAcceptedMeasurement("aabb", [])).toBe(false);
  });
});
