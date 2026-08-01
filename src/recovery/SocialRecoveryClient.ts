import { utf8ToBytes } from "../crypto/encoding";
import type { SocialRecoveryCredential } from "./SocialRecoveryCredential";

export type SocialRecoveryProvider = "google" | "apple" | "email";
export type SocialRecoveryAction = "enroll" | "recover";

export interface AttestationPolicy {
  audience: string;
  imageDigest: string;
  projectNumber: string;
  serviceAccount: string;
}

export interface SocialRecoveryClientOptions {
  baseUrl: string;
  appId: string;
  environment?: "development" | "production";
  /**
   * Values pinned by the developer from the Cavos environment configuration.
   * They must not be learned from the same control plane being attested.
   */
  attestation: AttestationPolicy;
}

export interface ProviderPolicy {
  app_id: string;
  environment_id: string;
  provider: SocialRecoveryProvider;
  issuer: string;
  audience: string;
  jwks_uri: string;
}

export type ChainAuthorization =
  | {
      chain: "starknet";
      chain_id_hex: string;
      account_hex: string;
      new_x_hex: string;
      new_y_hex: string;
      recovery_nonce: string;
      expires_at: number;
    }
  | {
      chain: "solana";
      account_b58_bytes_b64: string;
      new_pubkey_b64: string;
      /** Decimal u64 string; JavaScript numbers cannot represent every nonce. */
      recovery_nonce: string;
      expires_at: number;
    };

export interface SocialRecoveryResult {
  result: "enrolled" | "recovered";
  [key: string]: unknown;
}

interface StartedSession {
  session_id: string;
  provider: SocialRecoveryProvider;
  policy: ProviderPolicy;
  delay_seconds: number;
  resume_result?: SocialRecoveryResult;
}

interface ReadySession {
  session_id: string;
  action: SocialRecoveryAction;
  provider: SocialRecoveryProvider;
  status: string;
  ephemeral_public_key_b64?: string;
  attestation_nonce_b64?: string;
  attestation_claims?: { token?: string };
  sealed_record_b64?: string;
  result?: SocialRecoveryResult;
  error_code?: string;
}

/**
 * Real Google Confidential Space recovery transport.
 *
 * The OIDC credential and (for Stellar enrolment) DEK are encrypted in-browser
 * to an ephemeral P-256 key whose hash is bound into the Google attestation
 * token. The Cavos API only relays ciphertext.
 */
export class SocialRecoveryClient {
  constructor(private readonly opts: SocialRecoveryClientOptions) {}

  async enroll(params: {
    walletAddress: string;
    credential: SocialRecoveryCredential;
    stellarDek?: Uint8Array;
  }): Promise<{ sessionId: string; result: SocialRecoveryResult }> {
    const started = await this.start(
      params.walletAddress,
      "enroll",
      params.credential.tokenFingerprint,
    );
    if (started.resume_result?.result === "enrolled") {
      return { sessionId: started.session_id, result: started.resume_result };
    }
    const ready = await this.waitReady(started.session_id);
    await this.submitEncryptedJob(ready, {
      action: "enroll",
      credential: {
        provider: started.provider,
        id_token: params.credential.idToken,
        token_fingerprint: params.credential.tokenFingerprint,
      },
      policy: started.policy,
      stellar_dek_b64: params.stellarDek ? toB64(params.stellarDek) : undefined,
    });
    return {
      sessionId: started.session_id,
      result: await this.waitCompleted(started.session_id),
    };
  }

  async recover(params: {
    walletAddress: string;
    credential: SocialRecoveryCredential;
    authorizations?: ChainAuthorization[];
    stellarRecipientPublicKey?: Uint8Array;
  }): Promise<{ sessionId: string; result: SocialRecoveryResult }> {
    const started = await this.start(
      params.walletAddress,
      "recover",
      params.credential.tokenFingerprint,
    );
    const ready = await this.waitReady(started.session_id);
    if (!ready.sealed_record_b64) {
      throw new Error("kit/social-recovery: enrollment record is missing");
    }
    await this.submitEncryptedJob(ready, {
      action: "recover",
      credential: {
        provider: started.provider,
        id_token: params.credential.idToken,
        token_fingerprint: params.credential.tokenFingerprint,
      },
      sealed_record_b64: ready.sealed_record_b64,
      authorizations: params.authorizations ?? [],
      stellar_recipient_pubkey_b64: params.stellarRecipientPublicKey
        ? toB64(params.stellarRecipientPublicKey)
        : undefined,
    });
    return {
      sessionId: started.session_id,
      result: await this.waitCompleted(started.session_id),
    };
  }

  async confirmEnrollment(sessionId: string, txHash: string): Promise<void> {
    await this.fetchJson(`/api/recovery/social/sessions/${sessionId}/confirm`, {
      method: "POST",
      body: JSON.stringify({ tx_hash: txHash }),
    });
  }

  private async start(
    walletAddress: string,
    action: SocialRecoveryAction,
    authChallenge: string,
  ): Promise<StartedSession> {
    return this.fetchJson("/api/recovery/social/sessions", {
      method: "POST",
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        wallet_address: walletAddress,
        action,
        auth_challenge: authChallenge,
      }),
    });
  }

  private async waitReady(sessionId: string): Promise<ReadySession> {
    for (let attempt = 0; attempt < 180; attempt++) {
      const session = await this.session(sessionId);
      if (session.status === "ready") {
        await verifyAttestedChannel(session, this.opts.attestation);
        return session;
      }
      if (["failed", "expired"].includes(session.status)) {
        throw new Error(
          `kit/social-recovery: enclave startup failed (${session.error_code ?? session.status})`,
        );
      }
      await delay(2_000);
    }
    throw new Error("kit/social-recovery: enclave startup timed out");
  }

  private async waitCompleted(sessionId: string): Promise<SocialRecoveryResult> {
    for (let attempt = 0; attempt < 180; attempt++) {
      const session = await this.session(sessionId);
      if (session.status === "completed" && session.result) return session.result;
      if (["failed", "expired"].includes(session.status)) {
        throw new Error(
          `kit/social-recovery: recovery failed (${session.error_code ?? session.status})`,
        );
      }
      await delay(2_000);
    }
    throw new Error("kit/social-recovery: workload timed out");
  }

  private session(sessionId: string): Promise<ReadySession> {
    return this.fetchJson(`/api/recovery/social/sessions/${sessionId}`);
  }

  private async submitEncryptedJob(session: ReadySession, job: unknown): Promise<void> {
    if (!session.ephemeral_public_key_b64) {
      throw new Error("kit/social-recovery: enclave channel key is missing");
    }
    const encrypted = await encryptForEnclave(
      session.session_id,
      fromB64(session.ephemeral_public_key_b64),
      utf8ToBytes(JSON.stringify(job)),
    );
    await this.fetchJson(`/api/recovery/social/sessions/${session.session_id}/job`, {
      method: "POST",
      body: JSON.stringify(encrypted),
    });
  }

  private async fetchJson(path: string, init?: RequestInit): Promise<any> {
    const response = await fetch(new URL(path, this.opts.baseUrl), {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`kit/social-recovery: ${path} -> ${response.status} ${body}`);
    }
    return response.json();
  }
}

async function encryptForEnclave(
  sessionId: string,
  enclavePublicRaw: Uint8Array,
  plaintext: Uint8Array,
): Promise<{
  client_public_key_b64: string;
  nonce_b64: string;
  ciphertext_b64: string;
}> {
  const enclavePublic = await crypto.subtle.importKey(
    "raw",
    enclavePublicRaw as unknown as BufferSource,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const client = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: enclavePublic },
    client.privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aes = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8ToBytes(sessionId) as unknown as BufferSource,
      info: utf8ToBytes("cavos-confidential-channel-v1") as unknown as BufferSource,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce as unknown as BufferSource,
      additionalData: utf8ToBytes(sessionId) as unknown as BufferSource,
    },
    aes,
    plaintext as unknown as BufferSource,
  );
  const clientPublic = new Uint8Array(
    await crypto.subtle.exportKey("raw", client.publicKey),
  );
  return {
    client_public_key_b64: toB64(clientPublic),
    nonce_b64: toB64(nonce),
    ciphertext_b64: toB64(new Uint8Array(ciphertext)),
  };
}

async function verifyAttestedChannel(
  session: ReadySession,
  expected: AttestationPolicy,
): Promise<void> {
  // The control plane deliberately returns parsed claims for display only, but
  // the signed token itself must be available for independent SDK validation.
  const token = (session.attestation_claims as any)?.token as string | undefined;
  if (!token || !session.ephemeral_public_key_b64 || !session.attestation_nonce_b64) {
    throw new Error("kit/social-recovery: signed attestation is missing");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  if (!encodedSignature) throw new Error("kit/social-recovery: malformed attestation JWT");
  const header = JSON.parse(new TextDecoder().decode(fromB64(encodedHeader)));
  const claims = JSON.parse(new TextDecoder().decode(fromB64(encodedPayload)));
  if (header.alg !== "RS256" || typeof header.kid !== "string") {
    throw new Error("kit/social-recovery: unsupported attestation signature");
  }
  const jwksResponse = await fetch(
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com",
  );
  if (!jwksResponse.ok) throw new Error("kit/social-recovery: attestation JWKS unavailable");
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys?.find(
    (key: JsonWebKey & { kid?: string }) => key.kid === header.kid,
  );
  if (!jwk) throw new Error("kit/social-recovery: attestation signing key not found");
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    fromB64(encodedSignature) as unknown as BufferSource,
    utf8ToBytes(`${encodedHeader}.${encodedPayload}`) as unknown as BufferSource,
  );
  if (!valid) throw new Error("kit/social-recovery: invalid attestation signature");

  const nonce = toB64(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        concat(
          fromB64(session.ephemeral_public_key_b64),
          utf8ToBytes(session.session_id),
        ) as unknown as BufferSource,
      ),
    ),
  );
  const nonces = Array.isArray(claims.eat_nonce) ? claims.eat_nonce : [claims.eat_nonce];
  const support = claims.submods?.confidential_space?.support_attributes ?? [];
  if (
    claims.iss !== "https://confidentialcomputing.googleapis.com" ||
    claims.aud !== expected.audience ||
    claims.exp * 1000 <= Date.now() ||
    claims.swname !== "CONFIDENTIAL_SPACE" ||
    claims.dbgstat !== "disabled-since-boot" ||
    !support.includes("STABLE") ||
    claims.submods?.container?.image_digest !== expected.imageDigest ||
    claims.submods?.gce?.project_number !== expected.projectNumber ||
    !claims.google_service_accounts?.includes(expected.serviceAccount) ||
    !nonces.includes(nonce) ||
    nonce !== session.attestation_nonce_b64
  ) {
    throw new Error("kit/social-recovery: attestation policy mismatch");
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function toB64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64(value: string): Uint8Array {
  const normal = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normal.padEnd(Math.ceil(normal.length / 4) * 4, "="));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
