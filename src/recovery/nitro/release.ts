/**
 * Verification of published enclave releases.
 *
 * Pinning PCR0 in this package means every enclave redeploy breaks every kit
 * already shipped. Instead, each release of the enclave is built by GitHub
 * Actions in the public `cavos-recovery` repository and attested there with
 * Sigstore: a DSSE-signed in-toto statement naming the image's PCR0, PCR1 and
 * PCR2, signed with a short-lived Fulcio certificate bound to that workflow
 * run, and logged in Rekor. The browser accepts an enclave whose measurements
 * such a statement vouches for, so a new release needs no new SDK.
 *
 * What is trusted is fixed here, not by the host that serves the bundle: the
 * Sigstore public-good root, and the workflow identity in the certificate —
 * repository, its numeric id and owner id (which survive renames and cannot be
 * re-registered), GitHub-hosted runner, a push of a `v<N>` tag, and the release
 * workflow at that tag. The bundle arrives from an untrusted host and verifies
 * itself; a host can withhold a release but cannot forge one.
 */

import type { SigstoreBundle, TrustedRoot } from "@freedomofpress/sigstore-browser";
import trustedRoot from "./sigstoreTrustedRoot.json";

/**
 * The GitHub Actions workflow whose signed releases this build accepts.
 */
export interface EnclaveReleasePolicy {
  /** `owner/name` of the public repository that builds the enclave image. */
  repository: string;
  /** Numeric GitHub id of that repository. */
  repositoryId: string;
  /** Numeric GitHub id of the repository's owner. */
  ownerId: string;
  /** Path of the release workflow inside the repository. */
  workflow: string;
  /** Lowest release version accepted; raising it revokes every older release. */
  minVersion: number;
}

/**
 * The workflow identity a release certificate must carry.
 *
 * `trigger` and `ref` are fixed for Cavos releases; they are parameters only
 * so the signature path can be exercised against a real third-party bundle.
 */
export interface ReleaseSignerIdentity {
  repository: string;
  repositoryId: string;
  ownerId: string;
  workflow: string;
  trigger: string;
  ref: RegExp;
}

/** The contents of a verified release statement. */
export interface EnclaveRelease {
  imageDigest: string;
  pcr0: string;
  pcr1: string;
  pcr2: string;
  version: number;
  expiresAt: Date;
}

const BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const RELEASE_PREDICATE_TYPE = "https://cavos.xyz/attestation/enclave-release/v1";
const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const RELEASE_TAG = /^refs\/tags\/v([1-9][0-9]*)$/;
const PCR_HEX = /^[0-9a-f]{96}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const STATEMENT_FIELDS = ["_type", "subject", "predicateType", "predicate"];
const PREDICATE_FIELDS = ["pcr0", "pcr1", "pcr2", "version", "expiresAt"];

/**
 * Verify that `bundle` is a Cavos enclave release for exactly the attested
 * `pcrs`, and return its version.
 *
 * Throws on any failure; there is no partial success.
 */
export async function verifyEnclaveRelease(
  bundle: unknown,
  pcrs: Map<number, Uint8Array>,
  policy: EnclaveReleasePolicy,
  now: Date,
): Promise<number> {
  if (!Number.isSafeInteger(policy.minVersion) || policy.minVersion < 1) {
    throw new Error("kit/nitro: the release policy's minimum version is invalid");
  }
  const { payload, ref } = await verifyReleaseSignature(bundle, {
    repository: policy.repository,
    repositoryId: policy.repositoryId,
    ownerId: policy.ownerId,
    workflow: policy.workflow,
    trigger: "push",
    ref: RELEASE_TAG,
  });
  const release = parseReleaseStatement(payload);

  const tag = RELEASE_TAG.exec(ref);
  if (!tag || tag[1] !== String(release.version)) {
    throw new Error("kit/nitro: the release version does not match its signed tag");
  }
  if (release.version < policy.minVersion) {
    throw new Error("kit/nitro: the enclave release is older than this build accepts");
  }
  if (!(release.expiresAt.getTime() > now.getTime())) {
    throw new Error("kit/nitro: the enclave release has expired");
  }
  assertReleaseMatchesPcrs(release, pcrs);
  return release.version;
}

/**
 * Verify the bundle's Sigstore signature, transparency-log inclusion and
 * certificate identity, and return the signed statement with the tag it was
 * signed from.
 *
 * The bundled trusted root is tried first. If verification fails for any
 * reason other than the certificate identity, it is retried exactly once
 * against the root refreshed over TUF, then fails closed. A static root alone
 * would break old kits the day Sigstore adds a key — a new Rekor shard or
 * Fulcio intermediate — and new releases are logged under it. An identity
 * mismatch does not depend on the root, so it is not retried.
 */
export async function verifyReleaseSignature(
  bundle: unknown,
  identity: ReleaseSignerIdentity,
): Promise<{ payload: Uint8Array; ref: string }> {
  assertBundleShape(bundle);
  const sigstore = await import("@freedomofpress/sigstore-browser");

  let signedRef: string | undefined;
  const repositoryUrl = `https://github.com/${identity.repository}`;
  const policy = new sigstore.AllOf([
    new sigstore.OIDCIssuerV2(GITHUB_OIDC_ISSUER),
    new sigstore.OIDCSourceRepositoryURI(repositoryUrl),
    new sigstore.OIDCSourceRepositoryIdentifier(identity.repositoryId),
    new sigstore.OIDCSourceRepositoryOwnerIdentifier(identity.ownerId),
    new sigstore.OIDCRunnerEnvironment("github-hosted"),
    new sigstore.OIDCBuildTrigger(identity.trigger),
    {
      verify(cert) {
        const ref = cert.extSourceRepositoryRef?.sourceRepositoryRef;
        if (ref === undefined || !identity.ref.test(ref)) {
          throw new sigstore.PolicyError("the signing ref is not a release tag");
        }
        const buildConfig = cert.extBuildConfigURI?.buildConfigURI;
        if (buildConfig !== `${repositoryUrl}/${identity.workflow}@${ref}`) {
          throw new sigstore.PolicyError("the signing workflow is not the release workflow");
        }
        signedRef = ref;
      },
    },
  ]);

  const verify = async (refresh: boolean) => {
    const verifier = new sigstore.SigstoreVerifier({
      tlogThreshold: 1,
      ctlogThreshold: 1,
      tsaThreshold: 0,
    });
    if (refresh) {
      await verifier.loadSigstoreRootWithTUF();
    } else {
      await verifier.loadSigstoreRoot(trustedRoot as unknown as TrustedRoot);
    }
    return verifier.verifyDsse(bundle as SigstoreBundle, policy);
  };

  let verified: { payloadType: string; payload: Uint8Array };
  try {
    try {
      verified = await verify(false);
    } catch (error) {
      if (error instanceof sigstore.PolicyError) throw error;
      signedRef = undefined;
      verified = await verify(true);
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`kit/nitro: the enclave release signature is not valid: ${reason}`);
  }

  if (verified.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
    throw new Error("kit/nitro: the enclave release is not an in-toto statement");
  }
  if (signedRef === undefined) {
    throw new Error("kit/nitro: the enclave release identity was not checked");
  }
  return { payload: verified.payload, ref: signedRef };
}

/**
 * Parse a signed release statement, rejecting anything not exactly in the
 * expected shape. Pure: it checks content, not signatures.
 */
export function parseReleaseStatement(payload: Uint8Array): EnclaveRelease {
  let statement: unknown;
  try {
    statement = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch {
    throw new Error("kit/nitro: the release statement is not valid JSON");
  }
  if (!isPlainObject(statement)) {
    throw new Error("kit/nitro: the release statement is not an object");
  }
  if (statement._type !== STATEMENT_TYPE) {
    throw new Error("kit/nitro: the release statement is not an in-toto v1 statement");
  }
  assertOnlyFields(statement, STATEMENT_FIELDS, "release statement");
  if (statement.predicateType !== RELEASE_PREDICATE_TYPE) {
    throw new Error("kit/nitro: the release statement has an unexpected predicate type");
  }

  const subjects = statement.subject;
  if (!Array.isArray(subjects) || subjects.length !== 1) {
    throw new Error("kit/nitro: the release statement must name exactly one image");
  }
  const subject = subjects[0];
  if (!isPlainObject(subject) || !isPlainObject(subject.digest)) {
    throw new Error("kit/nitro: the release subject is malformed");
  }
  assertOnlyFields(subject, ["name", "digest"], "release subject");
  assertOnlyFields(subject.digest, ["sha256"], "release subject digest");
  if (subject.name !== undefined && typeof subject.name !== "string") {
    throw new Error("kit/nitro: the release subject is malformed");
  }
  const imageDigest = subject.digest.sha256;
  if (typeof imageDigest !== "string" || !SHA256_HEX.test(imageDigest)) {
    throw new Error("kit/nitro: the release subject digest is malformed");
  }

  const predicate = statement.predicate;
  if (!isPlainObject(predicate)) {
    throw new Error("kit/nitro: the release predicate is missing");
  }
  assertOnlyFields(predicate, PREDICATE_FIELDS, "release predicate");
  const [pcr0, pcr1, pcr2] = [predicate.pcr0, predicate.pcr1, predicate.pcr2];
  for (const pcr of [pcr0, pcr1, pcr2]) {
    if (typeof pcr !== "string" || !PCR_HEX.test(pcr)) {
      throw new Error("kit/nitro: the release measurements are malformed");
    }
  }
  const version = predicate.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
    throw new Error("kit/nitro: the release version is malformed");
  }
  const expiresAtValue = predicate.expiresAt;
  const expiresAt = typeof expiresAtValue === "string" ? new Date(expiresAtValue) : undefined;
  if (
    typeof expiresAtValue !== "string" ||
    !RFC3339_UTC.test(expiresAtValue) ||
    !expiresAt ||
    Number.isNaN(expiresAt.getTime())
  ) {
    throw new Error("kit/nitro: the release expiry is malformed");
  }

  return {
    imageDigest,
    pcr0: pcr0 as string,
    pcr1: pcr1 as string,
    pcr2: pcr2 as string,
    version,
    expiresAt,
  };
}

/**
 * Require the attested PCR0, PCR1 and PCR2 to be exactly the released ones.
 *
 * An all-zero PCR0 is what a debug-mode enclave reports; its memory is open to
 * the parent instance, so it is never accepted whatever a release says.
 */
export function assertReleaseMatchesPcrs(
  release: Pick<EnclaveRelease, "pcr0" | "pcr1" | "pcr2">,
  pcrs: Map<number, Uint8Array>,
): void {
  const attested = [0, 1, 2].map((index) => {
    const value = pcrs.get(index);
    if (!value || value.length === 0) {
      throw new Error(`kit/nitro: the attestation carries no PCR${index}`);
    }
    return toHex(value);
  });
  if (/^0+$/.test(attested[0])) {
    throw new Error("kit/nitro: the enclave runs in debug mode");
  }
  if (
    attested[0] !== release.pcr0 ||
    attested[1] !== release.pcr1 ||
    attested[2] !== release.pcr2
  ) {
    throw new Error("kit/nitro: the enclave measurements do not match the release");
  }
}

function assertBundleShape(bundle: unknown): void {
  if (!isPlainObject(bundle) || bundle.mediaType !== BUNDLE_MEDIA_TYPE) {
    throw new Error("kit/nitro: the enclave release is not a Sigstore v0.3 bundle");
  }
  const material = bundle.verificationMaterial;
  if (!isPlainObject(material) || "x509CertificateChain" in material) {
    throw new Error("kit/nitro: the enclave release must carry a single certificate");
  }
  if (!isPlainObject(bundle.dsseEnvelope)) {
    throw new Error("kit/nitro: the enclave release carries no DSSE envelope");
  }
}

function assertOnlyFields(value: Record<string, unknown>, allowed: string[], what: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new Error(`kit/nitro: the ${what} has unknown fields: ${unknown.sort().join(", ")}`);
  }
}

function isPlainObject(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
