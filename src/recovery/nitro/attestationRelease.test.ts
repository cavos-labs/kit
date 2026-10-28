import { verifyNitroAttestation } from "./attestation";
import { verifyEnclaveRelease, type EnclaveReleasePolicy } from "./release";
import { REAL_ATTESTATION_B64, REAL_ATTESTATION_TIMESTAMP } from "./fixtures/realAttestation";

jest.mock("./release", () => ({ verifyEnclaveRelease: jest.fn() }));

/**
 * How `verifyNitroAttestation` chooses between a pinned PCR0 and a signed
 * release, run on the genuine AWS document from `attestation.test.ts`.
 */

const REAL_PCR0 =
  "4b8d4cf2a99e05ce1b5bddaf9d21cb446eb0e606c5bebd1ebf02b473a22165f7b68b0bb0d1ac5a90f0311e493522cfab";
const now = new Date(REAL_ATTESTATION_TIMESTAMP);
const release: EnclaveReleasePolicy = {
  repository: "cavos-labs/cavos-recovery",
  repositoryId: "1333734222",
  ownerId: "216094156",
  workflow: ".github/workflows/release.yml",
  minVersion: 1,
};
const document = () => Uint8Array.from(Buffer.from(REAL_ATTESTATION_B64, "base64"));
const verifyRelease = verifyEnclaveRelease as jest.Mock;

beforeEach(() => {
  verifyRelease.mockReset();
  verifyRelease.mockResolvedValue(1);
});

describe("verifyNitroAttestation policy paths", () => {
  it("accepts a pinned PCR0 without consulting releases", async () => {
    const fetchRelease = jest.fn();
    await verifyNitroAttestation(document(), { pcr0: REAL_PCR0, release }, { now, fetchRelease });
    expect(fetchRelease).not.toHaveBeenCalled();
    expect(verifyRelease).not.toHaveBeenCalled();
  });

  it("verifies the release fetched for the attested PCR0 when it is not pinned", async () => {
    const bundle = { mediaType: "bundle" };
    const fetchRelease = jest.fn().mockResolvedValue(bundle);
    const attestation = await verifyNitroAttestation(
      document(),
      { pcr0: ["00".repeat(48)], release },
      { now, fetchRelease },
    );
    expect(fetchRelease).toHaveBeenCalledWith(REAL_PCR0);
    expect(verifyRelease).toHaveBeenCalledWith(bundle, attestation.pcrs, release, now);
  });

  it("accepts a release-only policy", async () => {
    const fetchRelease = jest.fn().mockResolvedValue({});
    await verifyNitroAttestation(document(), { release }, { now, fetchRelease });
    expect(verifyRelease).toHaveBeenCalledTimes(1);
  });

  it("rejects when the release does not verify", async () => {
    verifyRelease.mockRejectedValue(new Error("kit/nitro: the enclave release has expired"));
    await expect(
      verifyNitroAttestation(document(), { release }, { now, fetchRelease: jest.fn() }),
    ).rejects.toThrow(/expired/);
  });

  it("rejects when the release cannot be fetched", async () => {
    const fetchRelease = jest.fn().mockRejectedValue(new Error("no published release"));
    await expect(
      verifyNitroAttestation(document(), { release }, { now, fetchRelease }),
    ).rejects.toThrow(/no published release/);
    expect(verifyRelease).not.toHaveBeenCalled();
  });

  it("rejects an unpinned PCR0 when there is no way to fetch a release", async () => {
    await expect(verifyNitroAttestation(document(), { release }, { now })).rejects.toThrow(
      /image measurement is not accepted/,
    );
  });

  it("rejects a policy that names neither path", async () => {
    await expect(
      verifyNitroAttestation(document(), {}, { now, fetchRelease: jest.fn() }),
    ).rejects.toThrow(/accepts no enclave/);
  });
});
