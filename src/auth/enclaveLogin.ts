import { DEFAULT_SOCIAL_RECOVERY_ATTESTATION } from "../recovery/attestationDefaults";
import { fetchEnclaveRelease, runEnclaveJob, verifiedChannelKey } from "../recovery/enclaveChannel";
import type { AttestationPolicy } from "../recovery/SocialRecoveryClient";
import {
  ENCLAVE_EMAIL_ISSUER,
  ENCLAVE_GITHUB_ISSUER,
  ENCLAVE_TELEGRAM_ISSUER,
} from "../recovery/SocialRecoveryCredential";
import { normalizeEmailCode } from "./emailCode";
import type { WebCryptoLoginKey } from "./loginKey";

/** What the enclave is asked to verify. The login key and PKCE verifier come from the login that is in progress. */
export type LoginVerifyRequest =
  | { provider: "email"; email: string; code: string }
  | { provider: "github"; grant: string }
  | { provider: "telegram"; grant: string };

export interface EnclaveLoginOptions {
  appId: string;
  backendUrl: string;
  /** Defaults to the enclave shipped with this package. */
  attestation?: AttestationPolicy;
}

const ENCLAVE_LOGIN_ERRORS: Record<string, string> = {
  invalid_request: "Enter a valid email address.",
  app_not_found: "kit/auth: this app is not registered with Cavos.",
  email_undeliverable: "This email provider is not supported yet.",
  code_cooldown: "A code was just sent to this address. Wait a minute before requesting another.",
  rate_limited: "Too many attempts. Try again in a few minutes.",
  email_unavailable: "Email sign-in is unavailable right now. Try again later.",
  enclave_unavailable: "Sign-in is unavailable right now. Try again later.",
  enclave_release_unavailable: "Sign-in is unavailable right now. Try again later.",
  code_rejected: "That code is wrong or has expired. Request a new one.",
  github_rejected: "GitHub did not accept this sign-in. Try again.",
  telegram_rejected: "Telegram did not accept this sign-in. Try again.",
  invalid_grant: "This sign-in expired. Sign in again.",
};

const VERIFIERS = {
  email: {
    path: "/api/oauth/email/verify",
    result: "email_verified",
    issuer: ENCLAVE_EMAIL_ISSUER,
    label: "email",
    failure: "kit/auth: the enclave did not verify this email",
  },
  github: {
    path: "/api/oauth/github/verify",
    result: "github_verified",
    issuer: ENCLAVE_GITHUB_ISSUER,
    label: "GitHub",
    failure: "kit/auth: the enclave did not verify this GitHub sign-in",
  },
  telegram: {
    path: "/api/oauth/telegram/verify",
    result: "telegram_verified",
    issuer: ENCLAVE_TELEGRAM_ISSUER,
    label: "Telegram",
    failure: "kit/auth: the enclave did not verify this Telegram sign-in",
  },
} as const;

/** The request field that runs a login on an earlier enclave release; empty for the current one. */
export function enclaveReleaseOf(login: { enclaveRelease?: number }): { enclave_release?: number } {
  return login.enclaveRelease === undefined ? {} : { enclave_release: login.enclaveRelease };
}

/** POST JSON to the Cavos backend, turning the enclave login error codes into messages a user can act on. */
export async function enclavePost(backendUrl: string, path: string, body: unknown): Promise<any> {
  const response = await fetch(`${backendUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (response.ok) return response.json();
  const text = await response.text().catch(() => "");
  let code: unknown;
  try {
    code = JSON.parse(text)?.error;
  } catch {
    code = undefined;
  }
  const known = typeof code === "string" ? ENCLAVE_LOGIN_ERRORS[code] : undefined;
  throw new Error(known ?? `kit/auth: ${path} -> ${response.status} ${text}`);
}

/**
 * Open an attested enclave session, run one login job encrypted with the login
 * key and return the id_token the enclave signed.
 */
export async function runEnclaveLogin(
  opts: EnclaveLoginOptions,
  key: WebCryptoLoginKey,
  request: LoginVerifyRequest,
): Promise<string> {
  const verifier = VERIFIERS[request.provider];
  const release = enclaveReleaseOf(key);
  const session = await enclavePost(opts.backendUrl, "/api/oauth/email/session", { app_id: opts.appId, ...release });
  const sessionId: unknown = session?.session_id;
  if (typeof sessionId !== "string") {
    throw new Error("kit/auth: the enclave session carried no id");
  }
  const channelKey = await verifiedChannelKey(
    sessionId,
    session.attestation_document_b64,
    opts.attestation ?? DEFAULT_SOCIAL_RECOVERY_ATTESTATION,
    (pcr0Hex) => fetchEnclaveRelease(`${opts.backendUrl}/api/enclave/releases/${pcr0Hex}`),
  );
  const job =
    request.provider === "email"
      ? { action: "verify_email", email: request.email, code: normalizeEmailCode(request.code) }
      : { action: `verify_${request.provider}`, code_verifier: key.codeVerifier };
  const grant =
    request.provider === "email"
      ? {}
      : { [`${request.provider}_grant`]: request.grant };
  const result = await runEnclaveJob<{ result?: string; id_token?: unknown }>(
    sessionId,
    channelKey,
    key,
    job,
    (sealed) =>
      enclavePost(opts.backendUrl, verifier.path, { session_id: sessionId, job: sealed, ...grant, ...release }),
  );
  if (result.result !== verifier.result || typeof result.id_token !== "string") {
    throw new Error(verifier.failure);
  }
  if (parseIssuer(result.id_token) !== verifier.issuer) {
    throw new Error(`kit/auth: the ${verifier.label} token was not issued by the enclave`);
  }
  return result.id_token;
}

function parseIssuer(jwt: string): unknown {
  const part = jwt.split(".")[1];
  if (!part) throw new Error("kit/auth: malformed JWT");
  return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))).iss;
}
