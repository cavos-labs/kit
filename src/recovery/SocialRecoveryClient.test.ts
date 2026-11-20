import "fake-indexeddb/auto";
import { SIGN_IN_AGAIN_TO_RECOVER, SocialRecoveryClient } from "./SocialRecoveryClient";
import { createSocialRecoveryCredential } from "./SocialRecoveryCredential";
import { verifyNitroAttestation } from "./nitro/attestation";
import { WebCryptoLoginKey } from "../auth/loginKey";

jest.mock("./nitro/attestation", () => ({ verifyNitroAttestation: jest.fn() }));

const APP_ID = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";
const SESSION_ID = "7ee71f25-9f59-43f6-8091-317a94074209";
const text = (value: string) => new TextEncoder().encode(value);
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

function token(): string {
  const payload = Buffer.from(JSON.stringify({ iss: "https://accounts.google.com", sub: "u" })).toString("base64url");
  return `h.${payload}.s`;
}

async function enclave() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const binding = new Uint8Array(await crypto.subtle.digest("SHA-256", text(SESSION_ID)));
  (verifyNitroAttestation as jest.Mock).mockResolvedValue({ publicKey: publicRaw, userData: binding });
  const sent: { client_public_key_b64?: string }[] = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: { body: string }) => {
    if (String(url).endsWith("/api/recovery/social/sessions")) {
      return {
        ok: true,
        json: async () => ({
          session_id: SESSION_ID,
          provider: "google",
          policy: {},
          attestation_document_b64: "AAAA",
          sealed_record_b64: "AA",
        }),
      };
    }
    sent.push(JSON.parse(init!.body));
    return { ok: true, json: async () => ({}) };
  }) as unknown as typeof fetch;
  return sent;
}

describe("SocialRecoveryClient login key", () => {
  const realFetch = globalThis.fetch;
  afterEach(async () => {
    globalThis.fetch = realFetch;
    await WebCryptoLoginKey.remove(APP_ID);
  });

  const credential = createSocialRecoveryCredential(token());

  it("encrypts the job with the login key this context holds for the app", async () => {
    const sent = await enclave();
    const key = await WebCryptoLoginKey.create(APP_ID);
    const client = new SocialRecoveryClient({ baseUrl: "https://cavos.test", appId: APP_ID, attestation: {} as never });
    await expect(client.recover({ walletAddress: "0x1", credential })).rejects.toThrow("not authenticated");
    expect(sent[0].client_public_key_b64).toBe(b64(key.publicKeyRaw()));
  });

  it("refuses to run a job when no login is in progress", async () => {
    const sent = await enclave();
    const client = new SocialRecoveryClient({ baseUrl: "https://cavos.test", appId: APP_ID, attestation: {} as never });
    await expect(client.recover({ walletAddress: "0x1", credential })).rejects.toThrow("no sign-in in progress");
    expect(sent).toHaveLength(0);
  });

  it("uses the key a custom loader provides", async () => {
    const sent = await enclave();
    const key = await WebCryptoLoginKey.create("elsewhere");
    const client = new SocialRecoveryClient({
      baseUrl: "https://cavos.test",
      appId: APP_ID,
      attestation: {} as never,
      loginKey: async () => key,
    });
    await expect(client.recover({ walletAddress: "0x1", credential })).rejects.toThrow("not authenticated");
    expect(sent[0].client_public_key_b64).toBe(b64(key.publicKeyRaw()));
    await WebCryptoLoginKey.remove("elsewhere");
  });
});

describe("SocialRecoveryClient across enclave releases", () => {
  const realFetch = globalThis.fetch;
  afterEach(async () => {
    globalThis.fetch = realFetch;
    await WebCryptoLoginKey.signInWith(APP_ID, null);
    await WebCryptoLoginKey.remove(APP_ID);
  });

  const credential = createSocialRecoveryCredential(token());
  const client = () =>
    new SocialRecoveryClient({ baseUrl: "https://cavos.test", appId: APP_ID, attestation: {} as never });

  function refuseSessions(status: number, body: unknown) {
    const started: Record<string, unknown>[] = [];
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: { body: string }) => {
      started.push(JSON.parse(init!.body));
      return { ok: false, status, text: async () => JSON.stringify(body) };
    }) as unknown as typeof fetch;
    return started;
  }

  it("asks for another sign-in, on the release that holds the record, when a recovery needs one", async () => {
    refuseSessions(409, { error: "login_release_mismatch", enclave_release: 4 });
    await WebCryptoLoginKey.create(APP_ID);

    await expect(client().recover({ walletAddress: "0x1", credential })).rejects.toThrow(SIGN_IN_AGAIN_TO_RECOVER);
    expect((await WebCryptoLoginKey.create(APP_ID)).enclaveRelease).toBe(4);
  });

  it("tells the control plane which release the login ran on", async () => {
    const started = refuseSessions(503, { error: "enclave_unavailable" });
    await WebCryptoLoginKey.create(APP_ID);
    await expect(client().recover({ walletAddress: "0x1", credential })).rejects.toThrow("503");
    await WebCryptoLoginKey.signInWith(APP_ID, 4);
    await WebCryptoLoginKey.create(APP_ID);
    await expect(client().recover({ walletAddress: "0x1", credential })).rejects.toThrow("503");

    expect(started[0]).not.toHaveProperty("login_release");
    expect(started[1].login_release).toBe(4);
  });

  it("does not change the next sign-in for any other refusal, or for an enrolment", async () => {
    await WebCryptoLoginKey.create(APP_ID);
    refuseSessions(409, { error: "provider_mismatch", enrolled_provider: "apple" });
    await expect(client().recover({ walletAddress: "0x1", credential })).rejects.toThrow("provider_mismatch");
    refuseSessions(409, { error: "login_release_mismatch", enclave_release: 5 });
    await expect(client().enroll({ walletAddress: "0x1", credential })).rejects.toThrow("login_release_mismatch");

    expect((await WebCryptoLoginKey.create(APP_ID)).enclaveRelease).toBeUndefined();
  });
});
