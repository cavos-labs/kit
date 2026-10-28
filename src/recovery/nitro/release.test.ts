import { createHash } from "crypto";
import { readFileSync } from "fs";
import { join } from "path";
import { SigstoreVerifier } from "@freedomofpress/sigstore-browser";
import {
  assertReleaseMatchesPcrs,
  parseReleaseStatement,
  verifyEnclaveRelease,
  verifyReleaseSignature,
  type ReleaseSignerIdentity,
} from "./release";
import { DEFAULT_SOCIAL_RECOVERY_ATTESTATION } from "../attestationDefaults";
import trustedRoot from "./sigstoreTrustedRoot.json";

/**
 * The Sigstore path runs against a real public-good bundle: astral-sh/uv's
 * GitHub release attestation (Fulcio certificate, Rekor v1 dsse entry with an
 * inclusion proof). It is not a Cavos release, so the Cavos policy must refuse
 * it; pointed at uv's own workflow identity the signature must verify, and the
 * statement must then be refused for not being an enclave release.
 */

const uvBundle = () =>
  JSON.parse(readFileSync(join(__dirname, "fixtures/uvReleaseBundle.json"), "utf8"));

const uvIdentity: ReleaseSignerIdentity = {
  repository: "astral-sh/uv",
  repositoryId: "699532645",
  ownerId: "115962839",
  workflow: ".github/workflows/release.yml",
  trigger: "workflow_dispatch",
  ref: /^refs\/heads\/main$/,
};

const pcr = (byte: number) => new Uint8Array(48).fill(byte);
const pcrs = new Map([
  [0, pcr(0xaa)],
  [1, pcr(0xbb)],
  [2, pcr(0xcc)],
]);
const released = { pcr0: "aa".repeat(48), pcr1: "bb".repeat(48), pcr2: "cc".repeat(48) };

let tufRefresh: jest.SpyInstance;

beforeEach(() => {
  tufRefresh = jest
    .spyOn(SigstoreVerifier.prototype, "loadSigstoreRootWithTUF")
    .mockImplementation(function (this: SigstoreVerifier) {
      return this.loadSigstoreRoot(trustedRoot as any);
    });
});

afterEach(() => tufRefresh.mockRestore());

describe("bundled Sigstore trusted root", () => {
  it("is the pinned public-good trusted_root.json", () => {
    const bytes = readFileSync(join(__dirname, "sigstoreTrustedRoot.json"));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
    );
  });
});

describe("verifyReleaseSignature", () => {
  it("verifies a real public-good bundle under its own workflow identity", async () => {
    const { payload, ref } = await verifyReleaseSignature(uvBundle(), uvIdentity);
    expect(ref).toBe("refs/heads/main");
    expect(() => parseReleaseStatement(payload)).toThrow(/unexpected predicate type/);
    expect(tufRefresh).not.toHaveBeenCalled();
  });

  it("refuses the same bundle when any identity claim differs, without refreshing the root", async () => {
    const variants: Partial<ReleaseSignerIdentity>[] = [
      { repositoryId: "1" },
      { ownerId: "1" },
      { trigger: "push" },
      { ref: /^refs\/tags\/v([1-9][0-9]*)$/ },
      { workflow: ".github/workflows/other.yml" },
    ];
    for (const variant of variants) {
      await expect(
        verifyReleaseSignature(uvBundle(), { ...uvIdentity, ...variant }),
      ).rejects.toThrow(/signature is not valid/);
    }
    expect(tufRefresh).not.toHaveBeenCalled();
  });

  it("retries a non-identity failure exactly once against the refreshed root", async () => {
    const bundle = uvBundle();
    const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString());
    statement.predicateType = "https://cavos.xyz/attestation/enclave-release/v1";
    bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");

    await expect(verifyReleaseSignature(bundle, uvIdentity)).rejects.toThrow(
      /signature is not valid/,
    );
    expect(tufRefresh).toHaveBeenCalledTimes(1);
  });

  it("fails closed when the refreshed root cannot be loaded", async () => {
    tufRefresh.mockRejectedValue(new Error("offline"));
    const bundle = uvBundle();
    bundle.dsseEnvelope.signatures[0].sig = Buffer.alloc(70).toString("base64");
    await expect(verifyReleaseSignature(bundle, uvIdentity)).rejects.toThrow(/offline/);
  });

  it("rejects a bundle carrying a certificate chain", async () => {
    const bundle = uvBundle();
    bundle.verificationMaterial.x509CertificateChain = {
      certificates: [bundle.verificationMaterial.certificate],
    };
    await expect(verifyReleaseSignature(bundle, uvIdentity)).rejects.toThrow(/single certificate/);
  });

  it("rejects anything but a v0.3 bundle", async () => {
    const bundle = uvBundle();
    bundle.mediaType = "application/vnd.dev.sigstore.bundle+json;version=0.2";
    await expect(verifyReleaseSignature(bundle, uvIdentity)).rejects.toThrow(/v0.3 bundle/);
    await expect(verifyReleaseSignature(null, uvIdentity)).rejects.toThrow(/v0.3 bundle/);
  });
});

describe("verifyEnclaveRelease", () => {
  it("refuses a real bundle that was not signed by the Cavos release workflow", async () => {
    await expect(
      verifyEnclaveRelease(uvBundle(), pcrs, DEFAULT_SOCIAL_RECOVERY_ATTESTATION.release!, new Date()),
    ).rejects.toThrow(/OIDCSourceRepositoryURI does not match/);
    expect(tufRefresh).not.toHaveBeenCalled();
  });
});

function statement(overrides: Record<string, unknown> = {}, predicate: Record<string, unknown> = {}) {
  return new TextEncoder().encode(
    JSON.stringify({
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "enclave.eif", digest: { sha256: "ab".repeat(32) } }],
      predicateType: "https://cavos.xyz/attestation/enclave-release/v1",
      predicate: { ...released, version: 3, expiresAt: "2027-01-01T00:00:00Z", ...predicate },
      ...overrides,
    }),
  );
}

describe("parseReleaseStatement", () => {
  it("reads a well-formed release", () => {
    expect(parseReleaseStatement(statement())).toEqual({
      imageDigest: "ab".repeat(32),
      ...released,
      version: 3,
      expiresAt: new Date("2027-01-01T00:00:00Z"),
    });
  });

  it("rejects payloads that are not a JSON object", () => {
    expect(() => parseReleaseStatement(new TextEncoder().encode("nope"))).toThrow(/not valid JSON/);
    expect(() => parseReleaseStatement(new TextEncoder().encode("[]"))).toThrow(/not an object/);
    expect(() => parseReleaseStatement(Uint8Array.of(0xff))).toThrow(/not valid JSON/);
  });

  it("rejects the wrong statement or predicate type", () => {
    expect(() =>
      parseReleaseStatement(statement({ _type: "https://in-toto.io/Statement/v0.1" })),
    ).toThrow(/in-toto v1/);
    expect(() =>
      parseReleaseStatement(statement({ predicateType: "https://slsa.dev/provenance/v1" })),
    ).toThrow(/unexpected predicate type/);
  });

  it("rejects unknown statement, subject and predicate fields", () => {
    expect(() => parseReleaseStatement(statement({ extra: 1 }))).toThrow(/statement has unknown/);
    expect(() =>
      parseReleaseStatement(
        statement({ subject: [{ name: "x", digest: { sha256: "ab".repeat(32) }, uri: "y" }] }),
      ),
    ).toThrow(/subject has unknown/);
    expect(() =>
      parseReleaseStatement(
        statement({ subject: [{ digest: { sha256: "ab".repeat(32), sha512: "cd" } }] }),
      ),
    ).toThrow(/digest has unknown/);
    expect(() => parseReleaseStatement(statement({}, { pcr8: "00" }))).toThrow(
      /predicate has unknown/,
    );
  });

  it("requires exactly one image subject with a sha256 digest", () => {
    const subject = { digest: { sha256: "ab".repeat(32) } };
    expect(() => parseReleaseStatement(statement({ subject: [] }))).toThrow(/exactly one/);
    expect(() => parseReleaseStatement(statement({ subject: [subject, subject] }))).toThrow(
      /exactly one/,
    );
    expect(() =>
      parseReleaseStatement(statement({ subject: [{ digest: { sha256: "AB".repeat(32) } }] })),
    ).toThrow(/digest is malformed/);
  });

  it("requires lowercase 96-character measurements", () => {
    for (const value of ["AA".repeat(48), "aa".repeat(47), 7, undefined]) {
      expect(() => parseReleaseStatement(statement({}, { pcr1: value }))).toThrow(
        /measurements are malformed/,
      );
    }
  });

  it("requires a positive integer version", () => {
    for (const version of [0, -1, 1.5, "3", Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => parseReleaseStatement(statement({}, { version }))).toThrow(
        /version is malformed/,
      );
    }
  });

  it("requires an RFC 3339 UTC expiry", () => {
    for (const expiresAt of [
      "2027-01-01T00:00:00+01:00",
      "2027-01-01",
      "2027-13-01T00:00:00Z",
      1798761600,
    ]) {
      expect(() => parseReleaseStatement(statement({}, { expiresAt }))).toThrow(
        /expiry is malformed/,
      );
    }
  });
});

describe("assertReleaseMatchesPcrs", () => {
  it("accepts exactly the released measurements", () => {
    expect(() => assertReleaseMatchesPcrs(released, pcrs)).not.toThrow();
  });

  it("rejects any differing measurement", () => {
    for (const key of ["pcr0", "pcr1", "pcr2"] as const) {
      expect(() =>
        assertReleaseMatchesPcrs({ ...released, [key]: "dd".repeat(48) }, pcrs),
      ).toThrow(/do not match/);
    }
  });

  it("rejects a debug-mode enclave even when the release names it", () => {
    const debug = new Map(pcrs).set(0, new Uint8Array(48));
    expect(() =>
      assertReleaseMatchesPcrs({ ...released, pcr0: "00".repeat(48) }, debug),
    ).toThrow(/debug mode/);
  });

  it("rejects an attestation missing a measurement", () => {
    const missing = new Map(pcrs);
    missing.delete(2);
    expect(() => assertReleaseMatchesPcrs(released, missing)).toThrow(/no PCR2/);
  });
});
