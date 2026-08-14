import { utf8ToBytes } from "../crypto/encoding";
import type { SocialRecoveryCredential } from "./SocialRecoveryCredential";
import {
  verifyNitroAttestation,
  type NitroAttestationPolicy,
} from "./nitro/attestation";

export type SocialRecoveryProvider = "google" | "apple" | "email";
export type SocialRecoveryAction = "enroll" | "recover";

/**
 * Which enclave this build will talk to. See `attestationDefaults.ts`.
 */
export type AttestationPolicy = NitroAttestationPolicy;

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

/**
 * A started session. The enclave is already running, so this arrives ready and
 * attested in the same response — there is no `starting` state to wait out.
 */
interface StartedSession {
  session_id: string;
  provider: SocialRecoveryProvider;
  policy: ProviderPolicy;
  delay_seconds: number;
  ephemeral_public_key_b64?: string;
  attestation_document_b64?: string;
  sealed_record_b64?: string;
  resume_result?: SocialRecoveryResult;
}

/**
 * Talks to the Cavos recovery enclave.
 *
 * The OIDC credential and (for Stellar enrolment) DEK are encrypted in-browser
 * to a P-256 key held only by an AWS Nitro Enclave whose measurement this build
 * pins. The Cavos API and the enclave's parent instance relay ciphertext and
 * are not trusted with any of it.
 *
 * Two round trips, both synchronous: start a session, then run the job. The
 * previous Confidential Space transport had to prewarm a VM before login and
 * then poll two endpoints for up to two minutes while it booted.
 */
export class SocialRecoveryClient {
  constructor(private readonly opts: SocialRecoveryClientOptions) {}

  async enroll(params: {
    walletAddress: string;
    credential: SocialRecoveryCredential;
    stellarDek?: Uint8Array;
  }): Promise<{ sessionId: string; result: SocialRecoveryResult }> {
    const session = await this.start(
      params.walletAddress,
      "enroll",
      params.credential.tokenFingerprint,
    );
    if (session.resume_result?.result === "enrolled") {
      return { sessionId: session.session_id, result: session.resume_result };
    }

    const channelKey = await this.verifiedChannelKey(session);
    const result = await this.runJob(session.session_id, channelKey, {
      action: "enroll",
      credential: {
        provider: session.provider,
        id_token: params.credential.idToken,
        token_fingerprint: params.credential.tokenFingerprint,
      },
      policy: session.policy,
      stellar_dek_b64: params.stellarDek ? toB64(params.stellarDek) : undefined,
    });
    return { sessionId: session.session_id, result };
  }

  async recover(params: {
    walletAddress: string;
    credential: SocialRecoveryCredential;
    authorizations?: ChainAuthorization[];
    stellarRecipientPublicKey?: Uint8Array;
  }): Promise<{ sessionId: string; result: SocialRecoveryResult }> {
    const session = await this.start(
      params.walletAddress,
      "recover",
      params.credential.tokenFingerprint,
    );
    if (!session.sealed_record_b64) {
      throw new Error("kit/social-recovery: enrollment record is missing");
    }

    const channelKey = await this.verifiedChannelKey(session);
    const result = await this.runJob(session.session_id, channelKey, {
      action: "recover",
      credential: {
        provider: session.provider,
        id_token: params.credential.idToken,
        token_fingerprint: params.credential.tokenFingerprint,
      },
      sealed_record_b64: session.sealed_record_b64,
      authorizations: params.authorizations ?? [],
      stellar_recipient_pubkey_b64: params.stellarRecipientPublicKey
        ? toB64(params.stellarRecipientPublicKey)
        : undefined,
    });
    return { sessionId: session.session_id, result };
  }

  async confirmEnrollment(sessionId: string, txHash: string): Promise<void> {
    await this.fetchJson(`/api/recovery/social/sessions/${sessionId}/confirm`, {
      method: "POST",
      body: JSON.stringify({ tx_hash: txHash }),
    });
  }

  private start(
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

  /**
   * Verify the enclave's attestation and return the channel key **from inside
   * it**.
   *
   * This is the security boundary of the whole flow. The key is deliberately
   * read out of the signed document rather than from the JSON field beside it:
   * that way there is nothing to cross-check, because a relay that substituted
   * a key it controls would have to produce an AWS-signed document containing
   * it. `user_data` binds the document to this session, so a document minted
   * for one session cannot be replayed as the answer to another.
   */
  private async verifiedChannelKey(session: StartedSession): Promise<Uint8Array> {
    if (!session.attestation_document_b64) {
      throw new Error("kit/social-recovery: the session carried no attestation");
    }
    const attestation = await verifyNitroAttestation(
      fromB64(session.attestation_document_b64),
      this.opts.attestation,
    );

    if (!attestation.publicKey) {
      throw new Error("kit/social-recovery: the attestation carried no channel key");
    }
    const expectedBinding = new Uint8Array(
      await crypto.subtle.digest("SHA-256", utf8ToBytes(session.session_id) as unknown as BufferSource),
    );
    if (!attestation.userData || !bytesEqual(attestation.userData, expectedBinding)) {
      throw new Error("kit/social-recovery: the attestation is not bound to this session");
    }
    return attestation.publicKey;
  }

  /** Encrypt the job to the attested key and return the enclave's result. */
  private async runJob(
    sessionId: string,
    channelKey: Uint8Array,
    job: unknown,
  ): Promise<SocialRecoveryResult> {
    const encrypted = await encryptForEnclave(
      sessionId,
      channelKey,
      utf8ToBytes(JSON.stringify(job)),
    );
    const response = await this.fetchJson(
      `/api/recovery/social/sessions/${sessionId}/job`,
      { method: "POST", body: JSON.stringify(encrypted) },
    );
    if (!response?.result) {
      throw new Error("kit/social-recovery: the enclave returned no result");
    }
    return response.result as SocialRecoveryResult;
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
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
