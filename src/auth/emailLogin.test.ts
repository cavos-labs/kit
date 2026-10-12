import { CavosAuth } from "./CavosAuth";
import { loginNonce } from "./loginBinding";
import { EMAIL_CODE_LENGTH, normalizeEmailCode } from "./emailCode";
import { verifyNitroAttestation } from "../recovery/nitro/attestation";

jest.mock("../recovery/nitro/attestation", () => ({
  verifyNitroAttestation: jest.fn(),
}));

const APP_ID = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";
const SESSION_ID = "7ee71f25-9f59-43f6-8091-317a94074209";
const CODE = "qpzry9x8g";

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const unb64 = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const text = (value: string) => new TextEncoder().encode(value);

function unsignedJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from('{"alg":"ES256","typ":"JWT"}').toString("base64url");
  return `${header}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
}

interface FakeEnclave {
  fetch: jest.Mock;
  sentJob: () => Record<string, unknown>;
}

async function startEnclave(options: { nonceFor?: (clientNonce: string) => string } = {}): Promise<FakeEnclave> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const binding = new Uint8Array(await crypto.subtle.digest("SHA-256", text(SESSION_ID)));
  (verifyNitroAttestation as jest.Mock).mockResolvedValue({ publicKey: publicRaw, userData: binding });

  let job: Record<string, unknown> = {};
  const derive = async (clientPublicRaw: Uint8Array) => {
    const clientPublic = await crypto.subtle.importKey(
      "raw", clientPublicRaw as unknown as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: clientPublic }, pair.privateKey, 256);
    const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const key = (info: string) =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: text(SESSION_ID), info: text(info) },
        hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
      );
    return {
      request: await key("cavos-confidential-channel-v1"),
      response: await key("cavos-confidential-channel-v1/response"),
    };
  };

  const fetchMock = jest.fn(async (url: string, init: { body: string }) => {
    const body = JSON.parse(init.body);
    if (url.endsWith("/api/oauth/email/code")) {
      return { ok: true, json: async () => ({ status: "sent" }) };
    }
    if (url.endsWith("/api/oauth/email/session")) {
      return {
        ok: true,
        json: async () => ({
          session_id: SESSION_ID,
          ephemeral_public_key_b64: b64(publicRaw),
          attestation_document_b64: "AAAA",
        }),
      };
    }
    const keys = await derive(unb64(body.job.client_public_key_b64));
    const opened = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(body.job.nonce_b64) as unknown as BufferSource, additionalData: text(SESSION_ID) },
      keys.request,
      unb64(body.job.ciphertext_b64) as unknown as BufferSource,
    );
    job = JSON.parse(new TextDecoder().decode(opened));
    const clientNonce = job.client_nonce as string;
    const token = unsignedJwt({
      iss: "https://enclave.cavos.xyz",
      aud: "cavos-email",
      sub: "a".repeat(64),
      email: job.email,
      email_verified: true,
      nonce: options.nonceFor ? options.nonceFor(clientNonce) : `${APP_ID}.${clientNonce}`,
    });
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const sealed = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as unknown as BufferSource, additionalData: text(SESSION_ID) },
      keys.response,
      text(JSON.stringify({ result: "email_verified", id_token: token })),
    );
    return {
      ok: true,
      json: async () => ({ sealed_result: { nonce_b64: b64(nonce), ciphertext_b64: b64(new Uint8Array(sealed)) } }),
    };
  });
  return { fetch: fetchMock, sentJob: () => job };
}

describe("enclave email login", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
    jest.clearAllMocks();
  });

  function authWith(enclave: FakeEnclave) {
    globalThis.fetch = enclave.fetch as unknown as typeof fetch;
    return new CavosAuth({ backendUrl: "https://cavos.test", appId: APP_ID });
  }

  it("sends the normalised address to the code route", async () => {
    const enclave = await startEnclave();
    await authWith(enclave).sendOtp("  Ada@Example.COM ");
    expect(enclave.fetch).toHaveBeenCalledWith(
      "https://cavos.test/api/oauth/email/code",
      expect.objectContaining({ body: JSON.stringify({ app_id: APP_ID, email: "ada@example.com" }) }),
    );
  });

  it("verifies through the attested channel and keeps the login secret for recovery", async () => {
    const enclave = await startEnclave();
    const auth = authWith(enclave);
    const identity = await auth.verifyOtp(" Ada@Example.com", " QPZ-RY9 X8G ");

    expect(identity).toMatchObject({ email: "ada@example.com", provider: "email", userId: "a".repeat(64) });
    expect(enclave.sentJob()).toMatchObject({ action: "verify_email", email: "ada@example.com", code: CODE });
    const credential = auth.getSocialRecoveryCredential();
    expect(credential.provider).toBe("email");
    expect(credential.noncePreimage).toEqual(expect.any(String));
    expect(loginNonce(credential.noncePreimage!)).toBe(enclave.sentJob().client_nonce);
    expect(auth.getAuthToken()).toBe(credential.idToken);
  });

  it("refuses a token whose nonce is not this login's", async () => {
    const enclave = await startEnclave({ nonceFor: () => `${APP_ID}.${"x".repeat(43)}` });
    const auth = authWith(enclave);
    await expect(auth.verifyOtp("ada@example.com", CODE)).rejects.toThrow(/does not match this sign-in/);
    expect(auth.hasSocialRecoveryCredential()).toBe(false);
  });

  it("does not talk to an enclave whose attestation fails", async () => {
    const enclave = await startEnclave();
    (verifyNitroAttestation as jest.Mock).mockRejectedValue(new Error("kit/nitro: enclave image measurement is not accepted"));
    await expect(authWith(enclave).verifyOtp("ada@example.com", CODE)).rejects.toThrow(/not accepted/);
    expect(enclave.fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["code_cooldown", /just sent/],
    ["email_undeliverable", /not supported yet/],
    ["email_unavailable", /unavailable/],
  ])("explains %s", async (error, message) => {
    globalThis.fetch = (async () => ({
      ok: false,
      status: 422,
      text: async () => JSON.stringify({ error }),
    })) as unknown as typeof fetch;
    const auth = new CavosAuth({ backendUrl: "https://cavos.test", appId: APP_ID });
    await expect(auth.sendOtp("ada@example.com")).rejects.toThrow(message);
  });
});

describe("code input", () => {
  it("lower-cases and strips whitespace and hyphens", () => {
    expect(normalizeEmailCode(" QPZ-ry9\tx8G\n")).toBe(CODE);
    expect(normalizeEmailCode("qpzry9x8g")).toBe(CODE);
  });

  it("is nine characters", () => {
    expect(EMAIL_CODE_LENGTH).toBe(9);
    expect(CODE).toHaveLength(EMAIL_CODE_LENGTH);
  });
});
