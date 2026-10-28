import { bytesToBase64Url } from "../crypto/encoding";
import type { SocialRecoveryCredential } from "./SocialRecoveryCredential";
import type { NitroAttestationPolicy } from "./nitro/attestation";
import { fetchEnclaveRelease, runEnclaveJob, verifiedChannelKey } from "./enclaveChannel";

export type SocialRecoveryProvider = "google" | "apple" | "email" | "github";
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
  result: "enrolled" | "recovered" | "confirmed";
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
  ephemeral_public_key_b64?: string;
  attestation_document_b64?: string;
  /**
   * The wallet's existing record: always present for a recovery, and present
   * for an enrolment when the wallet already has one.
   */
  sealed_record_b64?: string;
}

/**
 * Talks to the Cavos recovery enclave.
 *
 * The OIDC credential is encrypted in-browser to a P-256 key held only by an
 * AWS Nitro Enclave whose measurement this build pins. The Cavos API and the
 * enclave's parent instance relay ciphertext and are not trusted with any of it.
 *
 * Two round trips, both synchronous: start a session, then run the job. The
 * previous Confidential Space transport had to prewarm a VM before login and
 * then poll two endpoints for up to two minutes while it booted.
 */
export class SocialRecoveryClient {
  constructor(private readonly opts: SocialRecoveryClientOptions) {}

  private readonly fetchRelease = (pcr0Hex: string): Promise<unknown> =>
    fetchEnclaveRelease(new URL(`/api/enclave/releases/${pcr0Hex}`, this.opts.baseUrl));

  async lookupDekEnrollment(params: {
    provider: SocialRecoveryCredential["provider"];
    subject: string;
    /** Proves the caller is `subject`; the answer names that person's wallet. */
    idToken: string;
  }): Promise<{ wallet_address: string } | null> {
    const query = new URLSearchParams({
      app_id: this.opts.appId,
      provider: params.provider,
      subject: params.subject,
    });
    if (this.opts.environment) query.set("environment", this.opts.environment);
    let row: { enrolled?: unknown; wallet_address?: unknown } | null = null;
    const url = new URL("/api/recovery/social/enrollment", this.opts.baseUrl);
    url.search = query.toString();
    try {
      const response = await fetch(url, {
        headers: { Accept: "application/json", Authorization: `Bearer ${params.idToken}` },
      });
      if (!response.ok) return null;
      row = await response.json();
    } catch {
      return null;
    }
    if (!row?.enrolled || typeof row.wallet_address !== "string" || !row.wallet_address) {
      return null;
    }
    return { wallet_address: row.wallet_address };
  }

  async enroll(params: {
    walletAddress: string;
    credential: SocialRecoveryCredential;
    dek?: Uint8Array;
  }): Promise<{ sessionId: string; result: SocialRecoveryResult }> {
    const session = await this.start(
      params.walletAddress,
      "enroll",
      params.credential,
      Boolean(params.dek),
    );
    const channelKey = await verifiedChannelKey(
      session.session_id,
      session.attestation_document_b64,
      this.opts.attestation,
      this.fetchRelease,
    );
    if (session.sealed_record_b64) {
      // The wallet already has a record. What it holds is the enclave's to say,
      // not the control plane's: a resumed Starknet enrolment installs this
      // public key on-chain for good, and "already protected" is only true if
      // the record really is this identity's and seals this device's DEK.
      const result = await this.runJob(session.session_id, channelKey, {
        action: "confirm",
        credential: jobCredential(params.credential),
        sealed_record_b64: session.sealed_record_b64,
        ...(params.dek ? { stellar_dek_b64: bytesToBase64Url(params.dek) } : {}),
      });
      return { sessionId: session.session_id, result };
    }
    const result = await this.runJob(session.session_id, channelKey, {
      action: "enroll",
      credential: jobCredential(params.credential),
      policy: session.policy,
      ...(params.dek ? { stellar_dek_b64: bytesToBase64Url(params.dek) } : {}),
    });
    return { sessionId: session.session_id, result };
  }

  async recover(params: {
    walletAddress: string;
    credential: SocialRecoveryCredential;
    authorizations?: ChainAuthorization[];
    recipientPublicSec1?: Uint8Array;
  }): Promise<{ sessionId: string; result: SocialRecoveryResult }> {
    const session = await this.start(
      params.walletAddress,
      "recover",
      params.credential,
    );
    if (!session.sealed_record_b64) {
      throw new Error("kit/social-recovery: enrollment record is missing");
    }

    const channelKey = await verifiedChannelKey(
      session.session_id,
      session.attestation_document_b64,
      this.opts.attestation,
      this.fetchRelease,
    );
    const result = await this.runJob(session.session_id, channelKey, {
      action: "recover",
      credential: jobCredential(params.credential),
      sealed_record_b64: session.sealed_record_b64,
      authorizations: params.authorizations ?? [],
      ...(params.recipientPublicSec1
        ? { stellar_recipient_pubkey_b64: bytesToBase64Url(params.recipientPublicSec1) }
        : {}),
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
    credential: SocialRecoveryCredential,
    dekEnroll = false,
  ): Promise<StartedSession> {
    return this.fetchJson("/api/recovery/social/sessions", {
      method: "POST",
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        wallet_address: walletAddress,
        action,
        // An app may offer every provider, so the one this credential came from
        // decides the policy. Control planes predating that ignore the field and
        // fall back to the environment's single configured provider.
        provider: credential.provider,
        auth_challenge: credential.tokenFingerprint,
        ...(dekEnroll ? { dek_enroll: true } : {}),
      }),
    });
  }

  private async runJob(
    sessionId: string,
    channelKey: Uint8Array,
    job: unknown,
  ): Promise<SocialRecoveryResult> {
    return runEnclaveJob<SocialRecoveryResult>(sessionId, channelKey, job, (encrypted) =>
      this.fetchJson(`/api/recovery/social/sessions/${sessionId}/job`, {
        method: "POST",
        body: JSON.stringify(encrypted),
      }),
    );
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

/**
 * The credential as the enclave reads it.
 *
 * `provider` is the credential's own, read from the token's `iss`, not one the
 * server echoed back: the enclave refuses a job whose credential provider
 * differs from its policy before it checks anything else.
 */
function jobCredential(credential: SocialRecoveryCredential) {
  return {
    provider: credential.provider,
    id_token: credential.idToken,
    token_fingerprint: credential.tokenFingerprint,
    ...(credential.noncePreimage ? { nonce_preimage: credential.noncePreimage } : {}),
  };
}
