import { base64UrlToBytes, bytesToUtf8, utf8ToBytes } from "../crypto/encoding";

/** Who may have signed a token, and for whom. */
export interface TokenIssuer {
  /** Every spelling of `iss` this issuer uses. */
  issuers: readonly string[];
  jwksUrl: string;
  /** The accepted `aud` values. Empty accepts any audience. */
  audiences: readonly string[];
}

export interface TokenClaims {
  sub: string;
  nonce?: unknown;
}

export type JwksLoader = (url: string) => Promise<JsonWebKey[]>;

interface SigningKey extends JsonWebKey {
  kid?: string;
}

const ALGORITHMS: Record<string, { import: RsaHashedImportParams | EcKeyImportParams; verify: AlgorithmIdentifier | EcdsaParams }> = {
  RS256: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: "RSASSA-PKCS1-v1_5" },
  ES256: { import: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" } },
};

/** Tokens are accepted this long after `exp`, for clocks that disagree. */
const CLOCK_SKEW_MS = 60_000;

/** The `iss` of a token, unverified: only good for choosing which issuer to verify it against. */
export function unverifiedIssuer(token: string): unknown {
  try {
    return decodeSegment(token.split(".")[1] ?? "").iss;
  } catch {
    return undefined;
  }
}

/**
 * Verify a JWT's signature against the issuer's published keys, then its
 * issuer, audience and expiry. Throws unless every check passes.
 */
export async function verifyIdToken(
  token: string,
  issuer: TokenIssuer,
  options: { now?: number; loadKeys?: JwksLoader } = {},
): Promise<TokenClaims> {
  const [headerPart, payloadPart, signaturePart, ...rest] = token.split(".");
  if (!headerPart || !payloadPart || !signaturePart || rest.length > 0) throw rejected("it is not a JWT");

  const header = decodeSegment(headerPart);
  const algorithm = typeof header.alg === "string" ? ALGORITHMS[header.alg] : undefined;
  if (!algorithm) throw rejected("its signature algorithm is not accepted");

  const keys = (await (options.loadKeys ?? fetchJwks)(issuer.jwksUrl)) as SigningKey[];
  const jwk = keys.find((key) => key.kid === header.kid);
  if (!jwk) throw rejected("no published key signed it");

  // Without `alg` and `use`, which name a JWS algorithm importKey may refuse; the import parameters decide.
  const { kty, n, e, crv, x, y } = jwk;
  const key = await crypto.subtle.importKey("jwk", { kty, n, e, crv, x, y }, algorithm.import, false, ["verify"]);
  const valid = await crypto.subtle.verify(
    algorithm.verify,
    key,
    base64UrlToBytes(signaturePart) as BufferSource,
    utf8ToBytes(`${headerPart}.${payloadPart}`) as BufferSource,
  );
  if (!valid) throw rejected("its signature does not verify");

  const claims = decodeSegment(payloadPart);
  if (!issuer.issuers.includes(claims.iss as string)) throw rejected("its issuer is not the expected one");
  if (issuer.audiences.length > 0 && !audiencesOf(claims.aud).some((aud) => issuer.audiences.includes(aud))) {
    throw rejected("it was issued for another application");
  }
  if (typeof claims.exp !== "number" || claims.exp * 1000 + CLOCK_SKEW_MS < (options.now ?? Date.now())) {
    throw rejected("it has expired");
  }
  if (typeof claims.sub !== "string" || !claims.sub) throw rejected("it names no user");
  return { sub: claims.sub, nonce: claims.nonce };
}

async function fetchJwks(url: string): Promise<JsonWebKey[]> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`kit/vault: could not read the sign-in keys (${response.status})`);
  const body = (await response.json()) as { keys?: unknown };
  if (!Array.isArray(body.keys)) throw new Error("kit/vault: the sign-in keys are malformed");
  return body.keys as JsonWebKey[];
}

function decodeSegment(segment: string): Record<string, unknown> {
  const value: unknown = JSON.parse(bytesToUtf8(base64UrlToBytes(segment)));
  if (typeof value !== "object" || value === null) throw rejected("it is not a JWT");
  return value as Record<string, unknown>;
}

function audiencesOf(aud: unknown): string[] {
  if (typeof aud === "string") return [aud];
  return Array.isArray(aud) ? aud.filter((value): value is string => typeof value === "string") : [];
}

function rejected(reason: string): Error {
  return new Error(`kit/vault: the sign-in token was refused: ${reason}`);
}
