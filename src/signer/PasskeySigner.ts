import { sha256 } from "@noble/hashes/sha256";
import type { DevicePublicKey } from "./DeviceSigner";
import {
  base64urlEncode,
  challengeOffsetOf,
  derToRs,
  spkiToPublicKey,
  type PasskeyAssertion,
} from "../crypto/webauthn";

export interface PasskeySignerOptions {
  /** Relying-Party id (usually the eTLD+1). Defaults to `window.location.hostname`. */
  rpId?: string;
  /** Human-readable RP name shown in the OS passkey UI. */
  rpName?: string;
}

export interface PasskeyEnrollParams {
  /** Stable user handle for the credential (e.g. the account address or userId). */
  userId: string;
  /** Account name shown in the OS passkey UI (e.g. an email). */
  userName: string;
  displayName?: string;
}

export interface EnrolledPasskey {
  publicKey: DevicePublicKey;
  credentialId: Uint8Array;
}

/**
 * Browser passkey signer. Creates a discoverable (resident) secp256r1 credential
 * that syncs across the user's devices (iCloud Keychain / Google Password
 * Manager), and produces WebAuthn assertions used to authorize `add_signer`.
 *
 * This is a step-up primitive: the app decides WHEN to enroll (e.g. after
 * onboarding, as a "turn on device approvals" / 2FA moment). Enrollment
 * registers the passkey on-chain as an approver; later, from any browser, an
 * assertion approves adding that browser's new device key.
 */
export class PasskeySigner {
  private readonly rpId: string;
  private readonly rpName: string;

  constructor(opts: PasskeySignerOptions = {}) {
    if (typeof window === "undefined" || !navigator.credentials) {
      throw new Error("kit/passkey: WebAuthn is only available in a browser");
    }
    this.rpId = opts.rpId ?? window.location.hostname;
    this.rpName = opts.rpName ?? this.rpId;
    // WebAuthn requires the RP ID to be a registrable domain (or "localhost").
    // An IP address always fails with a cryptic "invalid domain" — surface an
    // actionable message instead (common when devs test over a LAN IP).
    if (isIpAddress(this.rpId)) {
      throw new Error(
        `kit/passkey: passkeys can't use an IP address as the domain ("${this.rpId}"). ` +
          "Use http://localhost, a real HTTPS domain, or a tunnel (cloudflared/ngrok) — " +
          "or pass an explicit `rpId`. (The silent device key works over an IP; passkeys don't.)",
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

  /** Create a new synced passkey and return its P-256 public key. */
  async enroll(params: PasskeyEnrollParams): Promise<EnrolledPasskey> {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: buf(challenge),
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
          userVerification: "preferred",
        },
        attestation: "none",
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error("kit/passkey: enrollment cancelled");

    const response = cred.response as AuthenticatorAttestationResponse;
    const spki = new Uint8Array(response.getPublicKey()!);
    return { publicKey: spkiToPublicKey(spki), credentialId: new Uint8Array(cred.rawId) };
  }

  /**
   * Produce a WebAuthn assertion over `challenge` (a 32-byte value the caller
   * derives from the signer being added + the on-chain nonce). Uses discoverable
   * credentials — no `allowCredentials` — so it works on a brand-new browser.
   */
  async assert(challenge: Uint8Array): Promise<PasskeyAssertion> {
    const cred = (await navigator.credentials.get({
      publicKey: {
        challenge: buf(challenge),
        rpId: this.rpId,
        allowCredentials: [],
        userVerification: "preferred",
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error("kit/passkey: assertion cancelled");

    const response = cred.response as AuthenticatorAssertionResponse;
    const authenticatorData = new Uint8Array(response.authenticatorData);
    const clientDataJSON = new Uint8Array(response.clientDataJSON);
    const { r, s } = derToRs(new Uint8Array(response.signature));
    const challengeOffset = challengeOffsetOf(clientDataJSON, base64urlEncode(challenge));
    return { authenticatorData, clientDataJSON, r, s, challengeOffset };
  }
}

/**
 * WebAuthn requires the user handle to be 1..64 bytes. `userId` may be longer
 * (e.g. a 66-char Starknet address), so hash anything over 64 bytes to a stable
 * 32-byte handle. The handle is opaque — only its stability matters.
 */
/** True for IPv4/IPv6 literals — WebAuthn rejects these as an RP ID. */
function isIpAddress(host: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true; // IPv4
  if (host.includes(":")) return true; // IPv6 literal
  return false;
}

function userHandle(userId: string): Uint8Array {
  const bytes = new TextEncoder().encode(userId);
  return bytes.length <= 64 ? bytes : sha256(bytes);
}

/** Coerce a `Uint8Array` to the `BufferSource` the WebAuthn DOM types want
 * (works around the TS5.7 `ArrayBufferLike` vs `ArrayBuffer` mismatch). */
function buf(bytes: Uint8Array): BufferSource {
  return bytes.slice() as unknown as BufferSource;
}
