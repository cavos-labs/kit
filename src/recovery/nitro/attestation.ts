/**
 * Verification of AWS Nitro Enclaves attestation documents.
 *
 * This answers one question for the browser: *is the key I am about to encrypt
 * my Google credential to actually held by the enclave image Cavos published?*
 * Nothing else in the recovery flow is load-bearing for confidentiality — the
 * control plane and the enclave's parent instance only ever relay ciphertext —
 * so this file is the security boundary and is written to be read closely.
 *
 * The trust anchor is the AWS Nitro root certificate, pinned below as bytes. It
 * ships in this package rather than arriving from the recovery API for the same
 * reason the workload measurements do: an API that told the client which root
 * to trust could name its own, and the attestation would prove nothing.
 *
 * Document format: RFC 8949 CBOR, signed as a COSE_Sign1 structure with ES384.
 * See https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
 */

import { decodeCbor, encodeSigStructure, type CborValue } from "./cbor";
import { parseCertificate, type ParsedCertificate } from "./der";

/**
 * The AWS Nitro Attestation PKI root, DER-encoded.
 *
 * Verified against the fingerprint AWS publishes:
 *   64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:
 *   7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
 * Valid until 2049-10-28. `npm run verify:nitro-root` re-checks this constant
 * against the published certificate.
 */
const NITRO_ROOT_CERTIFICATE_B64 =
  "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMC" +
  "VVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5j" +
  "bGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0G" +
  "A1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2" +
  "MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSk" +
  "sfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQw" +
  "TcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5Yw" +
  "DgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5" +
  "W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/" +
  "nNr12UO8Yfwr6wPLb+6NIwLz3/Y=";

/** COSE algorithm identifier for ECDSA w/ SHA-384. */
const COSE_ALG_ES384 = -35;
/** COSE header label for the signing algorithm. */
const COSE_HEADER_ALG = 1;
/** CBOR tag identifying a COSE_Sign1 structure. */
const COSE_SIGN1_TAG = 18;
/** P-384 signatures are two 48-byte scalars. */
const P384_COORDINATE_BYTES = 48;

/**
 * How stale an attestation document may be. Documents are produced per session,
 * and the enclave answers in milliseconds, so a wide window buys nothing but
 * replay surface. Five minutes tolerates ordinary clock skew.
 */
const MAX_DOCUMENT_AGE_MS = 5 * 60_000;

/**
 * Which enclave the SDK is willing to talk to.
 *
 * `pcr0` accepts a list so an image rollout can overlap: publish the new
 * measurement alongside the one still deployed, ship the release, then
 * redeploy. Apps on either version keep working through the transition.
 * Order is newest first.
 */
export interface NitroAttestationPolicy {
  /** Accepted PCR0 values (hex, no `0x`) — the measurement of the enclave image. */
  pcr0: string | string[];
}

export interface NitroAttestationDocument {
  moduleId: string;
  timestamp: Date;
  pcrs: Map<number, Uint8Array>;
  /** The enclave's ephemeral channel key, as published in the document. */
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  nonce?: Uint8Array;
}

/**
 * Verify a Nitro attestation document and return its contents.
 *
 * Throws on any failure. Callers must treat a thrown error as "do not send this
 * enclave anything" — there is no partial success, and no field of the returned
 * document is meaningful unless the whole verification passed.
 *
 * `now` is injectable so tests can pin a moment inside a captured document's
 * validity window; production callers should leave it unset.
 */
export async function verifyNitroAttestation(
  document: Uint8Array,
  policy: NitroAttestationPolicy,
  options: { now?: Date } = {},
): Promise<NitroAttestationDocument> {
  const now = options.now ?? new Date();

  const { protectedHeader, payload, signature } = readCoseSign1(document);
  assertEs384(protectedHeader);

  const attestation = readAttestationDocument(payload);

  // Order matters below. The certificate chain establishes that AWS vouches for
  // the signing key; only then is it worth checking what the document says.
  const leaf = await verifyCertificateChain(attestation.certificate, attestation.cabundle, now);

  const signedRegion = encodeSigStructure(protectedHeader, new Uint8Array(0), payload);
  const signingKey = await importP384PublicKey(leaf.subjectPublicKeyInfo);
  const signatureIsValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-384" },
    signingKey,
    signature as unknown as BufferSource,
    signedRegion as unknown as BufferSource,
  );
  if (!signatureIsValid) {
    throw new Error("kit/nitro: attestation signature is invalid");
  }

  const age = now.getTime() - attestation.timestamp.getTime();
  if (age > MAX_DOCUMENT_AGE_MS) {
    throw new Error("kit/nitro: attestation document is stale");
  }
  // A document dated in the future is either clock skew or a replay attempt
  // against a rolled-back clock. Allow the same tolerance in both directions.
  if (age < -MAX_DOCUMENT_AGE_MS) {
    throw new Error("kit/nitro: attestation document is dated in the future");
  }

  const pcr0 = attestation.pcrs.get(0);
  if (!pcr0 || !isAcceptedMeasurement(toHex(pcr0), policy.pcr0)) {
    throw new Error("kit/nitro: enclave image measurement is not accepted");
  }

  return attestation;
}

/**
 * Whether an attested PCR0 is one this build accepts.
 *
 * An empty accepted list matches nothing: a policy that cannot be satisfied
 * must fail closed rather than wave everything past.
 */
export function isAcceptedMeasurement(
  attested: string | undefined | null,
  expected: string | string[],
): boolean {
  if (!attested) return false;
  const accepted = (Array.isArray(expected) ? expected : [expected]).map(normaliseHex);
  return accepted.length > 0 && accepted.includes(normaliseHex(attested));
}

function normaliseHex(value: string): string {
  return value.replace(/^0x/i, "").toLowerCase();
}

interface CoseSign1 {
  protectedHeader: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
}

function readCoseSign1(document: Uint8Array): CoseSign1 {
  let decoded = decodeCbor(document);

  // The structure may be tagged or untagged depending on the producer; the NSM
  // emits it tagged. Accept either, but reject any other tag.
  if (typeof decoded === "object" && decoded !== null && "tag" in decoded) {
    if (decoded.tag !== COSE_SIGN1_TAG) {
      throw new Error(`kit/nitro: unexpected CBOR tag ${decoded.tag}`);
    }
    decoded = decoded.value;
  }

  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error("kit/nitro: attestation is not a COSE_Sign1 structure");
  }

  const [protectedHeader, , payload, signature] = decoded;
  if (
    !(protectedHeader instanceof Uint8Array) ||
    !(payload instanceof Uint8Array) ||
    !(signature instanceof Uint8Array)
  ) {
    throw new Error("kit/nitro: malformed COSE_Sign1 fields");
  }
  if (signature.length !== P384_COORDINATE_BYTES * 2) {
    throw new Error("kit/nitro: unexpected signature length");
  }

  return { protectedHeader, payload, signature };
}

/**
 * Require that the signature really is ES384.
 *
 * Reading the algorithm from the protected header and then trusting it would be
 * pointless — the header is attacker-supplied. It is pinned to one value so a
 * document cannot ask to be verified under a weaker algorithm.
 */
function assertEs384(protectedHeader: Uint8Array): void {
  const header = decodeCbor(protectedHeader);
  if (!(header instanceof Map)) {
    throw new Error("kit/nitro: malformed COSE protected header");
  }
  if (header.get(COSE_HEADER_ALG) !== COSE_ALG_ES384) {
    throw new Error("kit/nitro: attestation is not signed with ES384");
  }
}

interface RawAttestation extends NitroAttestationDocument {
  certificate: Uint8Array;
  cabundle: Uint8Array[];
}

function readAttestationDocument(payload: Uint8Array): RawAttestation {
  const document = decodeCbor(payload);
  if (!(document instanceof Map)) {
    throw new Error("kit/nitro: attestation payload is not a map");
  }

  const moduleId = requireString(document, "module_id");
  const digest = requireString(document, "digest");
  // The PCR values are SHA-384 digests; any other digest function would mean
  // the measurements are not comparable to the ones this build pins.
  if (digest !== "SHA384") {
    throw new Error(`kit/nitro: unexpected PCR digest ${digest}`);
  }

  const timestampValue = document.get("timestamp");
  if (typeof timestampValue !== "number" && typeof timestampValue !== "bigint") {
    throw new Error("kit/nitro: attestation timestamp is missing");
  }

  const pcrsValue = document.get("pcrs");
  if (!(pcrsValue instanceof Map)) throw new Error("kit/nitro: attestation PCRs are missing");
  const pcrs = new Map<number, Uint8Array>();
  for (const [index, value] of pcrsValue) {
    if (typeof index !== "number" || !(value instanceof Uint8Array)) {
      throw new Error("kit/nitro: malformed PCR entry");
    }
    pcrs.set(index, value);
  }

  const certificate = document.get("certificate");
  if (!(certificate instanceof Uint8Array)) {
    throw new Error("kit/nitro: attestation certificate is missing");
  }

  const cabundleValue = document.get("cabundle");
  if (!Array.isArray(cabundleValue) || cabundleValue.length === 0) {
    throw new Error("kit/nitro: attestation CA bundle is missing");
  }
  const cabundle = cabundleValue.map((entry) => {
    if (!(entry instanceof Uint8Array)) throw new Error("kit/nitro: malformed CA bundle entry");
    return entry;
  });

  return {
    moduleId,
    timestamp: new Date(Number(timestampValue)),
    pcrs,
    certificate,
    cabundle,
    publicKey: optionalBytes(document, "public_key"),
    userData: optionalBytes(document, "user_data"),
    nonce: optionalBytes(document, "nonce"),
  };
}

function requireString(document: Map<CborValue, CborValue>, key: string): string {
  const value = document.get(key);
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`kit/nitro: attestation ${key} is missing`);
  }
  return value;
}

function optionalBytes(
  document: Map<CborValue, CborValue>,
  key: string,
): Uint8Array | undefined {
  const value = document.get(key);
  if (value === undefined || value === null) return undefined;
  if (!(value instanceof Uint8Array)) throw new Error(`kit/nitro: malformed ${key}`);
  // The NSM encodes "absent" as a zero-length string in some SDK versions.
  return value.length === 0 ? undefined : value;
}

/**
 * Validate the certificate path from the document's signing certificate up to
 * the pinned AWS root.
 *
 * AWS emits `cabundle` root-first (`[ROOT, INTERM_1, …, INTERM_N]`), so the
 * path runs in the opposite order. The bundle's own root is deliberately
 * discarded and replaced with the pinned one: trusting the root that arrived
 * alongside the document would make the whole chain self-signed by the
 * attacker.
 */
async function verifyCertificateChain(
  leafDer: Uint8Array,
  cabundle: Uint8Array[],
  now: Date,
): Promise<ParsedCertificate> {
  const root = parseCertificate(base64ToBytes(NITRO_ROOT_CERTIFICATE_B64));

  // [leaf, INTERM_N, …, INTERM_1] — the bundle's index 0 (its root) is dropped.
  const path = [leafDer, ...cabundle.slice(1).reverse()].map(parseCertificate);
  const leaf = path[0];

  // Each certificate is verified against the one above it, ending at the root.
  const issuers = [...path.slice(1), root];

  for (let index = 0; index < path.length; index += 1) {
    const subject = path[index];
    const issuer = issuers[index];

    if (now < subject.notBefore || now > subject.notAfter) {
      throw new Error("kit/nitro: a certificate in the chain is outside its validity window");
    }
    if (!bytesEqual(subject.issuer, issuer.subject)) {
      throw new Error("kit/nitro: certificate chain is not contiguous");
    }
    // Every certificate that signs another must be a CA. Without this, a leaf
    // certificate could be used to mint an apparently valid chain.
    if (!issuer.isCertificateAuthority) {
      throw new Error("kit/nitro: a non-CA certificate is used as an issuer");
    }

    const issuerKey = await importP384PublicKey(issuer.subjectPublicKeyInfo);
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      issuerKey,
      subject.signature as unknown as BufferSource,
      subject.tbs as unknown as BufferSource,
    );
    if (!valid) throw new Error("kit/nitro: certificate chain signature is invalid");
  }

  if (now < root.notBefore || now > root.notAfter) {
    throw new Error("kit/nitro: the pinned Nitro root certificate is expired");
  }

  return leaf;
}

function importP384PublicKey(spki: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    spki as unknown as BufferSource,
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"],
  );
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
