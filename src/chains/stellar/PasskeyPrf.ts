import { sha256 } from "@noble/hashes/sha256";

/**
 * WebAuthn **PRF** factor for the classic-G envelope.
 *
 * Unlike the Soroban passkey path (which needs an on-chain-verifiable *assertion
 * signature*), the classic-G account only needs a stable 32-byte secret to wrap
 * the DEK — exactly what the WebAuthn PRF extension provides: for a given
 * credential + input salt the authenticator returns the same 32 bytes on every
 * device the passkey syncs to (iCloud Keychain / Google Password Manager), and
 * that secret is derived inside the authenticator and never derivable by Cavos or
 * OAuth. That makes it the ideal synced anchor to approve a new device or recover.
 *
 * `getSecret()` returns the raw PRF output; callers pass it to
 * `derivePasskeyKEK` (via `CavosStellar.enrollPasskey` /
 * `approveThisDeviceWithPasskey`). Keeping this class free of any DEK/KEK logic
 * lets the account class stay runtime-agnostic and unit-testable.
 */

export interface PasskeyPrfOptions {
  /** Relying-Party id (usually the eTLD+1). Defaults to `window.location.hostname`. */
  rpId?: string;
  /** Human-readable RP name shown in the OS passkey UI. */
  rpName?: string;
}

export interface PasskeyPrfEnrollParams {
  /** Stable user handle for the credential (e.g. the account address or userId). */
  userId: string;
  /** Account name shown in the OS passkey UI (e.g. an email). */
  userName: string;
  displayName?: string;
}

/** Fixed PRF input salt — scopes the derived secret to the classic-G DEK factor.
 *  Stable forever: changing it changes every existing user's passkey secret. */
const PRF_SALT = sha256(new TextEncoder().encode("cavos-stellar-prf-v1"));

export class PasskeyPrf {
  private readonly rpId: string;
  private readonly rpName: string;

  constructor(opts: PasskeyPrfOptions = {}) {
    if (typeof window === "undefined" || !navigator.credentials) {
      throw new Error("kit/passkey-prf: WebAuthn is only available in a browser");
    }
    this.rpId = opts.rpId ?? window.location.hostname;
    this.rpName = opts.rpName ?? this.rpId;
    if (isIpAddress(this.rpId)) {
      throw new Error(
        `kit/passkey-prf: passkeys can't use an IP address as the domain ("${this.rpId}"). ` +
          "Use http://localhost, a real HTTPS domain, or a tunnel — or pass an explicit `rpId`.",
      );
    }
  }

  /** True if this platform advertises a usable passkey (platform authenticator). */
  static async isSupported(): Promise<boolean> {
    if (typeof window === "undefined" || !window.PublicKeyCredential) return false;
    try {
      return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  /**
   * Create a new synced, discoverable passkey with the PRF extension enabled, then
   * immediately read its PRF secret. Returns the credential id and the 32-byte
   * secret so the caller can enroll the passkey factor in one step. Some
   * authenticators don't return PRF results on create — in that case `secret` is
   * undefined and the caller should follow up with `getSecret()`.
   */
  async enroll(params: PasskeyPrfEnrollParams): Promise<{ credentialId: Uint8Array; secret?: Uint8Array }> {
    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: buf(crypto.getRandomValues(new Uint8Array(32))),
        rp: { id: this.rpId, name: this.rpName },
        user: {
          id: buf(userHandle(params.userId)),
          name: params.userName,
          displayName: params.displayName ?? params.userName,
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 (P-256)
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        attestation: "none",
        extensions: { prf: { eval: { first: buf(PRF_SALT) } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error("kit/passkey-prf: enrollment cancelled");
    return { credentialId: new Uint8Array(cred.rawId), secret: readPrf(cred) };
  }

  /**
   * Get the passkey's 32-byte PRF secret. Uses discoverable credentials (no
   * `allowCredentials`), so it works from a brand-new browser — the OS shows the
   * synced passkey picker. Throws if the authenticator doesn't support PRF.
   */
  async getSecret(): Promise<Uint8Array> {
    const cred = (await navigator.credentials.get({
      publicKey: {
        challenge: buf(crypto.getRandomValues(new Uint8Array(32))),
        rpId: this.rpId,
        allowCredentials: [],
        userVerification: "required",
        extensions: { prf: { eval: { first: buf(PRF_SALT) } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error("kit/passkey-prf: assertion cancelled");
    const secret = readPrf(cred);
    if (!secret) {
      throw new Error(
        "kit/passkey-prf: this authenticator did not return a PRF result — PRF is unsupported here",
      );
    }
    return secret;
  }
}

/** Read the 32-byte PRF `first` result from a credential's extension results. */
function readPrf(cred: PublicKeyCredential): Uint8Array | undefined {
  const results = (cred.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }).prf
    ?.results?.first;
  return results ? new Uint8Array(results) : undefined;
}

function isIpAddress(host: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  if (host.includes(":")) return true;
  return false;
}

function userHandle(userId: string): Uint8Array {
  const bytes = new TextEncoder().encode(userId);
  return bytes.length <= 64 ? bytes : sha256(bytes);
}

function buf(bytes: Uint8Array): BufferSource {
  return bytes.slice() as unknown as BufferSource;
}
