import { CavosAuth } from "./CavosAuth";
import { loginNonce, requiresLoginBinding } from "./loginBinding";
import { ENCLAVE_TELEGRAM_ISSUER } from "../recovery/SocialRecoveryCredential";
import { verifyNitroAttestation } from "../recovery/nitro/attestation";

jest.mock("../recovery/nitro/attestation", () => ({
  verifyNitroAttestation: jest.fn(),
}));

const APP_ID = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";
const SESSION_ID = "7ee71f25-9f59-43f6-8091-317a94074209";
const CALLBACK_CODE = "c".repeat(43);
const REDIRECT = "https://app.test/callback";

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const unb64 = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const text = (value: string) => new TextEncoder().encode(value);

function unsignedJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from('{"alg":"ES256","typ":"JWT"}').toString("base64url");
  return `${header}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
}

function telegramUrl(overrides: Record<string, string | null> = {}, base = "https://oauth.telegram.org/auth"): string {
  const params: Record<string, string | null> = {
    client_id: "123456",
    response_type: "code",
    scope: "openid profile",
    code_challenge_method: "S256",
    ...overrides,
  };
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== null) query.set(key, value);
  return `${base}?${query}`;
}

interface FakeTelegram {
  fetch: jest.Mock;
  authorizeUrl: () => string;
  sentJob: () => Record<string, unknown>;
  verifyBody: () => Record<string, unknown>;
}

interface FakeOptions {
  authorizeUrl?: (challenge: string, nonce: string) => string;
  issuer?: string;
  exchange?: Record<string, unknown>;
}

async function startTelegram(options: FakeOptions = {}): Promise<FakeTelegram> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const binding = new Uint8Array(await crypto.subtle.digest("SHA-256", text(SESSION_ID)));
  (verifyNitroAttestation as jest.Mock).mockResolvedValue({ publicKey: publicRaw, userData: binding });

  let job: Record<string, unknown> = {};
  let verifyBody: Record<string, unknown> = {};
  let authorize = "";
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

  const fetchMock = jest.fn(async (url: string, init?: { body: string }) => {
    if (url.includes("/api/oauth/v2/telegram")) {
      const requested = new URL(url).searchParams;
      const challenge = requested.get("code_challenge");
      const nonce = `${requested.get("app_id")}.${requested.get("nonce")}`;
      authorize = options.authorizeUrl
        ? options.authorizeUrl(challenge, nonce)
        : telegramUrl({ code_challenge: challenge!, nonce });
      return { ok: true, json: async () => ({ url: authorize }) };
    }
    if (url.endsWith("/api/oauth/callback/exchange")) {
      return { ok: true, json: async () => options.exchange ?? { telegram_grant: "grant-1" } };
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
    const body = JSON.parse(init!.body);
    verifyBody = body;
    const keys = await derive(unb64(body.job.client_public_key_b64));
    const opened = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(body.job.nonce_b64) as unknown as BufferSource, additionalData: text(SESSION_ID) },
      keys.request,
      unb64(body.job.ciphertext_b64) as unknown as BufferSource,
    );
    job = JSON.parse(new TextDecoder().decode(opened));
    const token = unsignedJwt({
      iss: options.issuer ?? ENCLAVE_TELEGRAM_ISSUER,
      aud: "cavos-telegram",
      sub: "b".repeat(64),
      name: "Ada Lovelace",
      preferred_username: "ada",
      nonce: `${APP_ID}.${loginNonce(job.login_secret as string)}`,
    });
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const sealed = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as unknown as BufferSource, additionalData: text(SESSION_ID) },
      keys.response,
      text(JSON.stringify({ result: "telegram_verified", id_token: token })),
    );
    return {
      ok: true,
      json: async () => ({ sealed_result: { nonce_b64: b64(nonce), ciphertext_b64: b64(new Uint8Array(sealed)) } }),
    };
  });
  return {
    fetch: fetchMock,
    authorizeUrl: () => authorize,
    sentJob: () => job,
    verifyBody: () => verifyBody,
  };
}

describe("Telegram login", () => {
  const realFetch = globalThis.fetch;
  const scope = globalThis as { window?: unknown };
  const hadWindow = "window" in scope;

  beforeEach(() => {
    scope.window = {};
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    if (!hadWindow) delete scope.window;
    jest.clearAllMocks();
  });

  function authWith(fake: FakeTelegram) {
    globalThis.fetch = fake.fetch as unknown as typeof fetch;
    return new CavosAuth({ backendUrl: "https://cavos.test", appId: APP_ID });
  }

  it("sends a PKCE challenge and a nonce derived from the login secret it keeps", async () => {
    const fake = await startTelegram();
    const auth = authWith(fake);
    const url = await auth.getTelegramOAuthUrl(REDIRECT);

    const requested = new URL(fake.fetch.mock.calls[0][0] as string);
    const challenge = requested.searchParams.get("code_challenge")!;
    expect(challenge).toHaveLength(43);
    expect(requested.searchParams.get("nonce")).toHaveLength(43);
    expect(requested.searchParams.get("redirect_uri")).toBe(REDIRECT);
    expect(requested.searchParams.get("app_id")).toBe(APP_ID);
    expect(url).toBe(fake.authorizeUrl());

    await auth.handleCallback(CALLBACK_CODE, REDIRECT);
    const job = fake.sentJob();
    expect(loginNonce(job.code_verifier as string)).toBe(challenge);
    expect(loginNonce(job.login_secret as string)).toBe(requested.searchParams.get("nonce"));
  });

  it("needs an appId", async () => {
    const auth = new CavosAuth({ backendUrl: "https://cavos.test" });
    await expect(auth.getTelegramOAuthUrl(REDIRECT)).rejects.toThrow(/needs an appId/);
  });

  it.each([
    ["is on another host", (c: string, n: string) => telegramUrl({ code_challenge: c, nonce: n }, "https://oauth.telegram.org.evil.test/auth")],
    ["is not https", (c: string, n: string) => telegramUrl({ code_challenge: c, nonce: n }, "http://oauth.telegram.org/auth")],
    ["is on another path", (c: string, n: string) => telegramUrl({ code_challenge: c, nonce: n }, "https://oauth.telegram.org/other")],
    ["has no challenge", (_c: string, n: string) => telegramUrl({ code_challenge: null, nonce: n })],
    ["has another challenge", (_c: string, n: string) => telegramUrl({ code_challenge: "z".repeat(43), nonce: n })],
    ["has the wrong method", (c: string, n: string) => telegramUrl({ code_challenge: c, nonce: n, code_challenge_method: "plain" })],
    ["has another app id in the nonce", (c: string, n: string) =>
      telegramUrl({ code_challenge: c, nonce: `other-app.${n.split(".")[1]}` })],
    ["has another client half in the nonce", (c: string) =>
      telegramUrl({ code_challenge: c, nonce: `${APP_ID}.${"y".repeat(43)}` })],
    ["has no nonce", (c: string) => telegramUrl({ code_challenge: c, nonce: null })],
    ["asks for the phone scope", (c: string, n: string) =>
      telegramUrl({ code_challenge: c, nonce: n, scope: "openid profile phone" })],
    ["asks only for openid", (c: string, n: string) => telegramUrl({ code_challenge: c, nonce: n, scope: "openid" })],
    ["is not a code flow", (c: string, n: string) => telegramUrl({ code_challenge: c, nonce: n, response_type: "token" })],
  ])("refuses a URL that %s", async (_name, authorizeUrl) => {
    const auth = authWith(await startTelegram({ authorizeUrl }));
    await expect(auth.getTelegramOAuthUrl(REDIRECT)).rejects.toThrow(
      "kit/auth: the Telegram sign-in URL is not the one this login asked for",
    );
  });

  it("verifies the grant through the attested channel and keeps the login secret for recovery", async () => {
    const fake = await startTelegram();
    const auth = authWith(fake);
    await auth.getTelegramOAuthUrl(REDIRECT);
    const identity = await auth.handleCallback(`?cavos_auth_code=${CALLBACK_CODE}`, REDIRECT);

    expect(identity).toMatchObject({ provider: "telegram", name: "Ada Lovelace", userId: "b".repeat(64) });
    const job = fake.sentJob();
    expect(Object.keys(job).sort()).toEqual(["action", "code_verifier", "login_secret"]);
    expect(job.action).toBe("verify_telegram");
    expect(job).not.toHaveProperty("client_nonce");
    expect(fake.verifyBody()).toMatchObject({ session_id: SESSION_ID, telegram_grant: "grant-1" });
    const credential = auth.getSocialRecoveryCredential();
    expect(credential.provider).toBe("telegram");
    expect(credential.noncePreimage).toBe(job.login_secret);
    expect(auth.getAuthToken()).toBe(credential.idToken);
  });

  it("refuses a callback this browser did not start", async () => {
    const auth = authWith(await startTelegram());
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/did not start here/);
    expect(auth.hasSocialRecoveryCredential()).toBe(false);
  });

  it("refuses a callback whose verifier is missing", async () => {
    const fake = await startTelegram();
    const auth = authWith(fake);
    await auth.getTelegramOAuthUrl(REDIRECT);
    (auth as unknown as { pkceVerifier: string | null }).pkceVerifier = null;
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/did not start here/);
  });

  it("refuses a callback whose login secret is missing", async () => {
    const fake = await startTelegram();
    const auth = authWith(fake);
    await auth.getTelegramOAuthUrl(REDIRECT);
    (auth as unknown as { loginSecret: string | null }).loginSecret = null;
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/did not start here/);
  });

  it("spends the verifier and secret on the first callback", async () => {
    const fake = await startTelegram();
    const auth = authWith(fake);
    await auth.getTelegramOAuthUrl(REDIRECT);
    await auth.handleCallback(CALLBACK_CODE, REDIRECT);
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/did not start here/);
  });

  it("refuses a token the enclave did not issue for Telegram", async () => {
    const fake = await startTelegram({ issuer: "https://enclave.cavos.xyz/github" });
    const auth = authWith(fake);
    await auth.getTelegramOAuthUrl(REDIRECT);
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(
      "kit/auth: the Telegram token was not issued by the enclave",
    );
    expect(auth.hasSocialRecoveryCredential()).toBe(false);
  });

  it("explains a rejected sign-in", async () => {
    const fake = await startTelegram();
    const auth = authWith(fake);
    await auth.getTelegramOAuthUrl(REDIRECT);
    const inner = fake.fetch.getMockImplementation()!;
    fake.fetch.mockImplementation(async (url: string, init?: { body: string }) =>
      url.endsWith("/api/oauth/telegram/verify")
        ? { ok: false, status: 422, text: async () => JSON.stringify({ error: "invalid_grant" }) }
        : inner(url, init),
    );
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/expired. Sign in again/);
  });

  it("binds the enclave's Telegram token to this login", () => {
    expect(requiresLoginBinding(ENCLAVE_TELEGRAM_ISSUER)).toBe(true);
    expect(requiresLoginBinding(`${ENCLAVE_TELEGRAM_ISSUER}/`)).toBe(false);
  });
});
