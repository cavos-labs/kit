import { verifyEnclaveRelease, type EnclaveReleasePolicy } from "./release";

/**
 * The checks `verifyEnclaveRelease` makes on top of a valid signature, against
 * the real identity policy classes. Only `SigstoreVerifier` is replaced: it
 * runs the policy against a certificate carrying the claims below and returns
 * the statement, standing in for a bundle Cavos has not published yet.
 */

const signed: { claims: Record<string, string>; statement: unknown } = {
  claims: {},
  statement: undefined,
};

jest.mock("@freedomofpress/sigstore-browser", () => {
  const actual = jest.requireActual("@freedomofpress/sigstore-browser");
  class FakeVerifier {
    async loadSigstoreRoot() {}
    async loadSigstoreRootWithTUF() {}
    async verifyDsse(_bundle: unknown, policy: { verify(cert: unknown): Promise<void> }) {
      const c = signed.claims;
      await policy.verify({
        extFulcioIssuerV2: { issuer: c.issuer },
        extSourceRepositoryURI: { sourceRepositoryURI: c.repositoryUri },
        extSourceRepositoryIdentifier: { sourceRepositoryIdentifier: c.repositoryId },
        extSourceRepositoryOwnerIdentifier: { sourceRepositoryOwnerIdentifier: c.ownerId },
        extRunnerEnvironment: { runnerEnvironment: c.runner },
        extBuildTrigger: { buildTrigger: c.trigger },
        extSourceRepositoryRef: { sourceRepositoryRef: c.ref },
        extBuildConfigURI: { buildConfigURI: c.buildConfig },
      });
      return {
        payloadType: "application/vnd.in-toto+json",
        payload: new TextEncoder().encode(JSON.stringify(signed.statement)),
      };
    }
  }
  return { ...actual, SigstoreVerifier: FakeVerifier };
});

const policy: EnclaveReleasePolicy = {
  repository: "cavos-labs/cavos-recovery",
  repositoryId: "1333734222",
  ownerId: "216094156",
  workflow: ".github/workflows/release.yml",
  minVersion: 2,
};

const pcrs = new Map([
  [0, new Uint8Array(48).fill(0xaa)],
  [1, new Uint8Array(48).fill(0xbb)],
  [2, new Uint8Array(48).fill(0xcc)],
]);
const now = new Date("2026-10-28T00:00:00Z");
const bundle = {
  mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
  verificationMaterial: { certificate: { rawBytes: "" } },
  dsseEnvelope: {},
};

function release(version: number, ref = `refs/tags/v${version}`, predicate: object = {}) {
  signed.claims = {
    issuer: "https://token.actions.githubusercontent.com",
    repositoryUri: "https://github.com/cavos-labs/cavos-recovery",
    repositoryId: "1333734222",
    ownerId: "216094156",
    runner: "github-hosted",
    trigger: "push",
    ref,
    buildConfig: `https://github.com/cavos-labs/cavos-recovery/.github/workflows/release.yml@${ref}`,
  };
  signed.statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "enclave.eif", digest: { sha256: "ab".repeat(32) } }],
    predicateType: "https://cavos.xyz/attestation/enclave-release/v1",
    predicate: {
      pcr0: "aa".repeat(48),
      pcr1: "bb".repeat(48),
      pcr2: "cc".repeat(48),
      version,
      expiresAt: "2026-12-01T00:00:00Z",
      ...predicate,
    },
  };
}

describe("verifyEnclaveRelease policy", () => {
  it("accepts a release signed from its own tag and returns its version", async () => {
    release(3);
    await expect(verifyEnclaveRelease(bundle, pcrs, policy, now)).resolves.toBe(3);
  });

  it("rejects each identity claim that differs from the Cavos release workflow", async () => {
    const claims: Record<string, string> = {
      issuer: "https://accounts.google.com",
      repositoryUri: "https://github.com/cavos-labs/other",
      repositoryId: "1",
      ownerId: "1",
      runner: "self-hosted",
      trigger: "workflow_dispatch",
      buildConfig:
        "https://github.com/cavos-labs/cavos-recovery/.github/workflows/other.yml@refs/tags/v3",
    };
    for (const [claim, value] of Object.entries(claims)) {
      release(3);
      signed.claims[claim] = value;
      await expect(verifyEnclaveRelease(bundle, pcrs, policy, now)).rejects.toThrow(
        /signature is not valid/,
      );
    }
  });

  it("rejects refs that are not a v<N> release tag", async () => {
    for (const ref of ["refs/heads/main", "refs/tags/v03", "refs/tags/v3-rc1", "refs/tags/3"]) {
      release(3, ref);
      await expect(verifyEnclaveRelease(bundle, pcrs, policy, now)).rejects.toThrow(
        /not a release tag/,
      );
    }
  });

  it("rejects a version that differs from the signed tag", async () => {
    release(4, "refs/tags/v3");
    await expect(verifyEnclaveRelease(bundle, pcrs, policy, now)).rejects.toThrow(
      /does not match its signed tag/,
    );
  });

  it("rejects a release older than the minimum version", async () => {
    release(1);
    await expect(verifyEnclaveRelease(bundle, pcrs, policy, now)).rejects.toThrow(/older/);
  });

  it("rejects an invalid minimum version in the policy", async () => {
    release(3);
    for (const minVersion of [0, NaN, 1.5]) {
      await expect(
        verifyEnclaveRelease(bundle, pcrs, { ...policy, minVersion }, now),
      ).rejects.toThrow(/minimum version is invalid/);
    }
  });

  it("rejects an expired release", async () => {
    release(3, undefined, { expiresAt: "2026-10-28T00:00:00Z" });
    await expect(verifyEnclaveRelease(bundle, pcrs, policy, now)).rejects.toThrow(/expired/);
  });

  it("rejects a release for different measurements", async () => {
    release(3, undefined, { pcr2: "dd".repeat(48) });
    await expect(verifyEnclaveRelease(bundle, pcrs, policy, now)).rejects.toThrow(
      /do not match the release/,
    );
  });
});
