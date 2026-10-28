import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToUtf8,
  utf8ToBytes,
} from "../crypto/encoding";
import { verifyNitroAttestation, type NitroAttestationPolicy } from "./nitro/attestation";

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
export async function verifiedChannelKey(
  sessionId: string,
  attestationDocumentB64: string | undefined,
  policy: NitroAttestationPolicy,
  fetchRelease?: (pcr0Hex: string) => Promise<unknown>,
): Promise<Uint8Array> {
  if (!attestationDocumentB64) {
    throw new Error("kit/social-recovery: the session carried no attestation");
  }
  const attestation = await verifyNitroAttestation(
    base64UrlToBytes(attestationDocumentB64),
    policy,
    { fetchRelease },
  );

  if (!attestation.publicKey) {
    throw new Error("kit/social-recovery: the attestation carried no channel key");
  }
  const expectedBinding = new Uint8Array(
    await crypto.subtle.digest("SHA-256", utf8ToBytes(sessionId) as unknown as BufferSource),
  );
  if (!attestation.userData || !bytesEqual(attestation.userData, expectedBinding)) {
    throw new Error("kit/social-recovery: the attestation is not bound to this session");
  }
  return attestation.publicKey;
}

/**
 * Fetch the signed release bundle the Cavos API serves for an enclave image.
 *
 * The host is not trusted: it can only withhold a release, because the bundle
 * is verified against Sigstore before anything in it is believed.
 */
export async function fetchEnclaveRelease(url: string | URL): Promise<unknown> {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (response.status === 404) {
    throw new Error("kit/social-recovery: this enclave image has no published release");
  }
  if (!response.ok) {
    throw new Error(`kit/social-recovery: the enclave release lookup failed (${response.status})`);
  }
  try {
    return await response.json();
  } catch {
    throw new Error("kit/social-recovery: the enclave release is not JSON");
  }
}

/**
 * Encrypt a job to the attested key, hand it to `send`, and return the
 * enclave's answer opened from its sealed copy.
 *
 * Only the sealed copy is used. Any plain `result` beside it is for the control
 * plane to persist; everything on the way back here could rewrite it, and the
 * sealed copy opens only under a key this client shares with the attested
 * enclave.
 */
export async function runEnclaveJob<T>(
  sessionId: string,
  channelKey: Uint8Array,
  job: unknown,
  send: (encrypted: {
    client_public_key_b64: string;
    nonce_b64: string;
    ciphertext_b64: string;
  }) => Promise<any>,
): Promise<T> {
  const { encrypted, openResult } = await encryptForEnclave<T>(
    sessionId,
    channelKey,
    utf8ToBytes(JSON.stringify(job)),
  );
  const response = await send(encrypted);
  const sealed = response?.sealed_result;
  if (typeof sealed?.nonce_b64 !== "string" || typeof sealed?.ciphertext_b64 !== "string") {
    throw new Error("kit/social-recovery: the enclave's answer was not authenticated");
  }
  return openResult(sealed);
}

export async function encryptForEnclave<T = unknown>(
  sessionId: string,
  enclavePublicRaw: Uint8Array,
  plaintext: Uint8Array,
): Promise<{
  encrypted: { client_public_key_b64: string; nonce_b64: string; ciphertext_b64: string };
  /** Open the enclave's sealed answer to this job. */
  openResult(sealed: { nonce_b64: string; ciphertext_b64: string }): Promise<T>;
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
  // One exchange, two keys: the request and the answer are sealed under
  // different `info` so neither direction can be replayed as the other
  // (RFC 9180 §9.8).
  const channelKey = (info: string, usage: KeyUsage) =>
    crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: utf8ToBytes(sessionId) as unknown as BufferSource,
        info: utf8ToBytes(info) as unknown as BufferSource,
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      [usage],
    );
  const aes = await channelKey("cavos-confidential-channel-v1", "encrypt");
  const responseKey = await channelKey("cavos-confidential-channel-v1/response", "decrypt");
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
    encrypted: {
      client_public_key_b64: bytesToBase64Url(clientPublic),
      nonce_b64: bytesToBase64Url(nonce),
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ciphertext)),
    },
    async openResult(sealed) {
      let plaintext: ArrayBuffer;
      try {
        plaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: base64UrlToBytes(sealed.nonce_b64) as unknown as BufferSource,
            additionalData: utf8ToBytes(sessionId) as unknown as BufferSource,
          },
          responseKey,
          base64UrlToBytes(sealed.ciphertext_b64) as unknown as BufferSource,
        );
      } catch {
        throw new Error("kit/social-recovery: the enclave's answer failed authentication");
      }
      return JSON.parse(bytesToUtf8(new Uint8Array(plaintext))) as T;
    },
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}
