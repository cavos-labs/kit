import { CavosAuth } from "./CavosAuth";
import { loginNonce, requiresLoginBinding } from "./loginBinding";
import { ENCLAVE_GITHUB_ISSUER } from "../recovery/SocialRecoveryCredential";
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

interface FakeGitHub {
  fetch: jest.Mock;
  authorizeUrl: () => string;
  sentJob: () => Record<string, unknown>;
  verifyBody: () => Record<string, unknown>;
}

interface FakeOptions {
  authorizeUrl?: (challenge: string | null) => string;
  issuer?: string;
  exchange?: Record<string, unknown>;
}

async function startGitHub(options: FakeOptions = {}): Promise<FakeGitHub> {
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
    if (url.includes("/api/oauth/v2/github")) {
      const challenge = new URL(url).searchParams.get("code_challenge");
      authorize = options.authorizeUrl
        ? options.authorizeUrl(challenge)
        : `https://github.com/login/oauth/authorize?client_id=x&code_challenge=${challenge}&code_challenge_method=S256`;
      return { ok: true, json: async () => ({ url: authorize }) };
    }
    if (url.endsWith("/api/oauth/callback/exchange")) {
      return { ok: true, json: async () => options.exchange ?? { github_grant: "grant-1" } };
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
      iss: options.issuer ?? ENCLAVE_GITHUB_ISSUER,
      aud: "cavos-github",
      sub: "b".repeat(64),
      name: "Ada Lovelace",
      preferred_username: "ada",
      nonce: `${APP_ID}.${job.client_nonce as string}`,
    });
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const sealed = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as unknown as BufferSource, additionalData: text(SESSION_ID) },
      keys.response,
      text(JSON.stringify({ result: "github_verified", id_token: token })),
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

describe("GitHub login", () => {
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

  function authWith(fake: FakeGitHub) {
    globalThis.fetch = fake.fetch as unknown as typeof fetch;
    return new CavosAuth({ backendUrl: "https://cavos.test", appId: APP_ID });
  }

  it("sends a PKCE challenge that is S256 of the verifier it keeps", async () => {
    const fake = await startGitHub();
    const auth = authWith(fake);
    const url = await auth.getGitHubOAuthUrl(REDIRECT);

    const requested = new URL(fake.fetch.mock.calls[0][0] as string);
    const challenge = requested.searchParams.get("code_challenge")!;
    expect(challenge).toHaveLength(43);
    expect(requested.searchParams.get("redirect_uri")).toBe(REDIRECT);
    expect(requested.searchParams.get("app_id")).toBe(APP_ID);
    expect(requested.searchParams.has("nonce")).toBe(false);
    expect(url).toBe(fake.authorizeUrl());

    await auth.handleCallback(CALLBACK_CODE, REDIRECT);
    expect(loginNonce(fake.sentJob().code_verifier as string)).toBe(challenge);
  });

  it("needs an appId", async () => {
    const auth = new CavosAuth({ backendUrl: "https://cavos.test" });
    await expect(auth.getGitHubOAuthUrl(REDIRECT)).rejects.toThrow(/needs an appId/);
  });

  it.each([
    ["has no challenge", () => "https://github.com/login/oauth/authorize?client_id=x"],
    [
      "has another challenge",
      () => `https://github.com/login/oauth/authorize?code_challenge=${"z".repeat(43)}&code_challenge_method=S256`,
    ],
    [
      "has the wrong method",
      (c: string | null) => `https://github.com/login/oauth/authorize?code_challenge=${c}&code_challenge_method=plain`,
    ],
    [
      "is on another host",
      (c: string | null) => `https://github.com.evil.test/login/oauth/authorize?code_challenge=${c}&code_challenge_method=S256`,
    ],
    [
      "is on another path",
      (c: string | null) => `https://github.com/login/device?code_challenge=${c}&code_challenge_method=S256`,
    ],
    [
      "is not https",
      (c: string | null) => `http://github.com/login/oauth/authorize?code_challenge=${c}&code_challenge_method=S256`,
    ],
  ])("refuses a URL that %s", async (_name, authorizeUrl) => {
    const auth = authWith(await startGitHub({ authorizeUrl }));
    await expect(auth.getGitHubOAuthUrl(REDIRECT)).rejects.toThrow(/not the one this login asked for/);
  });

  it("verifies the grant through the attested channel and keeps the login secret for recovery", async () => {
    const fake = await startGitHub();
    const auth = authWith(fake);
    await auth.getGitHubOAuthUrl(REDIRECT);
    const identity = await auth.handleCallback(`?cavos_auth_code=${CALLBACK_CODE}`, REDIRECT);

    expect(identity).toMatchObject({ provider: "github", name: "Ada Lovelace", userId: "b".repeat(64) });
    expect(fake.sentJob()).toMatchObject({ action: "verify_github" });
    expect(fake.verifyBody()).toMatchObject({ session_id: SESSION_ID, github_grant: "grant-1" });
    const credential = auth.getSocialRecoveryCredential();
    expect(credential.provider).toBe("github");
    expect(loginNonce(credential.noncePreimage!)).toBe(fake.sentJob().client_nonce);
    expect(auth.getAuthToken()).toBe(credential.idToken);
  });

  it("refuses a callback this browser did not start", async () => {
    const auth = authWith(await startGitHub());
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/did not start here/);
    expect(auth.hasSocialRecoveryCredential()).toBe(false);
  });

  it("spends the verifier and secret on the first callback", async () => {
    const fake = await startGitHub();
    const auth = authWith(fake);
    await auth.getGitHubOAuthUrl(REDIRECT);
    await auth.handleCallback(CALLBACK_CODE, REDIRECT);
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/did not start here/);
  });

  it("refuses a token the enclave did not issue for GitHub", async () => {
    const fake = await startGitHub({ issuer: "https://enclave.cavos.xyz" });
    const auth = authWith(fake);
    await auth.getGitHubOAuthUrl(REDIRECT);
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/not issued by the enclave/);
    expect(auth.hasSocialRecoveryCredential()).toBe(false);
  });

  it("explains a rejected sign-in", async () => {
    const fake = await startGitHub();
    const auth = authWith(fake);
    await auth.getGitHubOAuthUrl(REDIRECT);
    const inner = fake.fetch.getMockImplementation()!;
    fake.fetch.mockImplementation(async (url: string, init?: { body: string }) =>
      url.endsWith("/api/oauth/github/verify")
        ? { ok: false, status: 422, text: async () => JSON.stringify({ error: "invalid_grant" }) }
        : inner(url, init),
    );
    await expect(auth.handleCallback(CALLBACK_CODE, REDIRECT)).rejects.toThrow(/expired. Sign in again/);
  });

  it("binds the enclave's GitHub token to this login", () => {
    expect(requiresLoginBinding(ENCLAVE_GITHUB_ISSUER)).toBe(true);
    expect(requiresLoginBinding(`${ENCLAVE_GITHUB_ISSUER}/`)).toBe(false);
  });
});
