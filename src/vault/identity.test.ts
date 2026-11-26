import "fake-indexeddb/auto";
import { loginNonceOf } from "../auth/loginBinding";
import { WebCryptoLoginKey } from "../auth/loginKey";
import { bytesToBase64Url, utf8ToBytes } from "../crypto/encoding";
import { createGatekeeper, parseIdentitySettings, type IdentitySettings } from "./identity";
import { verifyIdToken, type TokenIssuer } from "./idToken";
import { SIGN_IN_REQUIRED } from "./protocol";
import { memorySessions, SESSION_IDLE_MS, SESSION_MAX_MS } from "./session";

const APP_ID = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";
const GOOGLE_CLIENT = "cavos-google-client";
const GOOGLE = "https://accounts.google.com";
const EXTERNAL = "https://auth.app.test";
const NOW = 1_800_000_000_000;

interface Signer {
  jwk: JsonWebKey & { kid: string };
  sign(claims: Record<string, unknown>, header?: Record<string, unknown>): Promise<string>;
}

const encode = (value: unknown) => bytesToBase64Url(utf8ToBytes(JSON.stringify(value)));

async function signer(kid: string, alg: "RS256" | "ES256" = "RS256"): Promise<Signer> {
  const params =
    alg === "RS256"
      ? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }
      : { name: "ECDSA", namedCurve: "P-256" };
  const pair = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid };
  return {
    jwk,
    async sign(claims, header = {}) {
      const signed = `${encode({ alg, kid, typ: "JWT", ...header })}.${encode(claims)}`;
      const algorithm = alg === "RS256" ? "RSASSA-PKCS1-v1_5" : { name: "ECDSA", hash: "SHA-256" };
      const signature = await crypto.subtle.sign(algorithm, pair.privateKey, utf8ToBytes(signed) as BufferSource);
      return `${signed}.${bytesToBase64Url(new Uint8Array(signature))}`;
    },
  };
}

const future = Math.floor(Date.now() / 1000) + 3600;

describe("verifyIdToken", () => {
  const issuer: TokenIssuer = { issuers: [GOOGLE], jwksUrl: "https://keys.test", audiences: [GOOGLE_CLIENT] };
  const claims = { iss: GOOGLE, aud: GOOGLE_CLIENT, sub: "u1", exp: NOW / 1000 + 60, nonce: "n" };

  it.each(["RS256", "ES256"] as const)("accepts a token its issuer signed with %s", async (alg) => {
    const google = await signer("k1", alg);
    const verified = await verifyIdToken(await google.sign(claims), issuer, { now: NOW, loadKeys: async () => [google.jwk] });
    expect(verified).toEqual({ sub: "u1", nonce: "n" });
  });

  it("refuses a token signed by a key the issuer did not publish", async () => {
    const google = await signer("k1");
    const attacker = await signer("k1");
    const forged = await attacker.sign(claims);
    await expect(verifyIdToken(forged, issuer, { now: NOW, loadKeys: async () => [google.jwk] })).rejects.toThrow("signature does not verify");
    const unknownKey = await (await signer("k2")).sign(claims);
    await expect(verifyIdToken(unknownKey, issuer, { now: NOW, loadKeys: async () => [google.jwk] })).rejects.toThrow("no published key");
  });

  it("refuses an unsigned token and a symmetric one", async () => {
    const google = await signer("k1");
    const body = encode(claims);
    for (const alg of ["none", "HS256"]) {
      const token = `${encode({ alg, kid: "k1" })}.${body}.${bytesToBase64Url(new Uint8Array(32))}`;
      await expect(verifyIdToken(token, issuer, { now: NOW, loadKeys: async () => [google.jwk] })).rejects.toThrow("algorithm is not accepted");
    }
  });

  it("refuses another issuer, another audience, an expired token and one that names no user", async () => {
    const google = await signer("k1");
    const check = async (changed: Record<string, unknown>) =>
      verifyIdToken(await google.sign({ ...claims, ...changed }), issuer, { now: NOW, loadKeys: async () => [google.jwk] });
    await expect(check({ iss: "https://evil.test" })).rejects.toThrow("issuer");
    await expect(check({ aud: "another-client" })).rejects.toThrow("another application");
    await expect(check({ exp: NOW / 1000 - 120 })).rejects.toThrow("expired");
    await expect(check({ exp: undefined })).rejects.toThrow("expired");
    await expect(check({ sub: "" })).rejects.toThrow("names no user");
  });
});

describe("sessions", () => {
  it("stay live while used and end a week after the last use", async () => {
    let now = NOW;
    const sessions = memorySessions(() => now);
    await sessions.open("k");
    now += SESSION_IDLE_MS - 1;
    expect(await sessions.renew("k")).toBe(true);
    now += SESSION_IDLE_MS - 1;
    expect(await sessions.renew("k")).toBe(true);
    now += SESSION_IDLE_MS;
    expect(await sessions.renew("k")).toBe(false);
  });

  it("end thirty days after sign-in however often they are used", async () => {
    let now = NOW;
    const sessions = memorySessions(() => now);
    await sessions.open("k");
    while (now < NOW + SESSION_MAX_MS - SESSION_IDLE_MS) {
      now += SESSION_IDLE_MS / 2;
      expect(await sessions.renew("k")).toBe(true);
    }
    now = NOW + SESSION_MAX_MS;
    expect(await sessions.renew("k")).toBe(false);
  });

  it("are gone once ended, and unknown users have none", async () => {
    const sessions = memorySessions();
    await sessions.open("k");
    await sessions.end("k");
    expect(await sessions.renew("k")).toBe(false);
    expect(await sessions.renew("other")).toBe(false);
  });
});

describe("the vault's gatekeeper", () => {
  afterEach(() => WebCryptoLoginKey.remove(APP_ID));

  async function gatekeeper(settings: Partial<IdentitySettings> = {}) {
    const google = await signer("g1");
    const external = await signer("e1");
    const sessions = memorySessions();
    const gate = createGatekeeper({
      appId: APP_ID,
      backendUrl: "https://cavos.test",
      settings: { google: [GOOGLE_CLIENT], apple: [], ...settings },
      sessions,
      loadKeys: async (url) => (url.startsWith("https://cavos.test/api/vault/identity-keys") ? [external.jwk] : [google.jwk]),
    });
    /** Start a login in the vault and return the Google token that answers it. */
    const signIn = async (sub: string, changed: Record<string, unknown> = {}) => {
      const key = await WebCryptoLoginKey.create(APP_ID);
      const nonce = `${APP_ID}.${loginNonceOf(key.publicKeyRaw())}`;
      return google.sign({ iss: GOOGLE, aud: GOOGLE_CLIENT, sub, exp: future, nonce, ...changed });
    };
    return { gate, google, external, signIn };
  }

  it("opens nothing for a user id alone", async () => {
    const { gate } = await gatekeeper();
    await expect(gate.admit("victim", null)).rejects.toThrow(SIGN_IN_REQUIRED);
  });

  it("opens a session for the token that answers the vault's login, then needs no token", async () => {
    const { gate, signIn } = await gatekeeper();
    await gate.admit("u1", await signIn("u1"));
    await expect(gate.admit("u1", null)).resolves.toBeUndefined();
    await expect(gate.admit("u2", null)).rejects.toThrow(SIGN_IN_REQUIRED);
  });

  it("refuses a token for another user, another client or another login", async () => {
    const { gate, google, signIn } = await gatekeeper();
    await expect(gate.admit("victim", await signIn("attacker"))).rejects.toThrow("another user");
    await expect(gate.admit("u1", await signIn("u1", { aud: "another-client" }))).rejects.toThrow("another application");
    await signIn("u1");
    const elsewhere = await google.sign({ iss: GOOGLE, aud: GOOGLE_CLIENT, sub: "u1", exp: future, nonce: `${APP_ID}.${"x".repeat(43)}` });
    await expect(gate.admit("u1", elsewhere)).rejects.toThrow("does not match this sign-in");
    await expect(gate.admit("u1", null)).rejects.toThrow(SIGN_IN_REQUIRED);
  });

  it("refuses a forged token", async () => {
    const { gate, signIn } = await gatekeeper();
    await signIn("u1");
    const attacker = await signer("g1");
    const key = await WebCryptoLoginKey.load(APP_ID);
    const forged = await attacker.sign({
      iss: GOOGLE,
      aud: GOOGLE_CLIENT,
      sub: "u1",
      exp: future,
      nonce: `${APP_ID}.${loginNonceOf(key!.publicKeyRaw())}`,
    });
    await expect(gate.admit("u1", forged)).rejects.toThrow("signature does not verify");
  });

  it("locks the wallet on sign-out, and the old token does not reopen it", async () => {
    const { gate, signIn } = await gatekeeper();
    const token = await signIn("u1");
    await gate.admit("u1", token);
    await gate.signOut("u1");
    await expect(gate.admit("u1", null)).rejects.toThrow(SIGN_IN_REQUIRED);
    await expect(gate.admit("u1", token)).rejects.toThrow("did not start here");
  });

  it("refuses every Google token when it could not read the app's client ids", async () => {
    const { gate, signIn } = await gatekeeper({ google: [] });
    await expect(gate.admit("u1", await signIn("u1"))).rejects.toThrow(SIGN_IN_REQUIRED);
  });

  it("opens a session for the user of an enclave sign-in the vault ran", async () => {
    const { gate } = await gatekeeper();
    await gate.signedIn(`h.${encode({ iss: "https://enclave.cavos.xyz", sub: "email-user" })}.s`);
    await expect(gate.admit("email-user", null)).resolves.toBeUndefined();
  });

  describe("for an app that signs its users in itself", () => {
    const settings = { external: { issuer: EXTERNAL, audience: "app-audience" } };
    const claims = { iss: EXTERNAL, aud: "app-audience", sub: "user_1", exp: future };

    it("opens the wallet for a valid token of the app's provider, every time", async () => {
      const { gate, external } = await gatekeeper(settings);
      await gate.admit("user_1", await external.sign(claims));
      await expect(gate.admit("user_1", null)).rejects.toThrow(SIGN_IN_REQUIRED);
    });

    it("refuses another user's token, another audience, an expired token and a forged one", async () => {
      const { gate, external } = await gatekeeper(settings);
      await expect(gate.admit("victim", await external.sign(claims))).rejects.toThrow("another user");
      await expect(gate.admit("user_1", await external.sign({ ...claims, aud: "other" }))).rejects.toThrow("another application");
      await expect(gate.admit("user_1", await external.sign({ ...claims, exp: 1 }))).rejects.toThrow("expired");
      const forged = await (await signer("e1")).sign(claims);
      await expect(gate.admit("user_1", forged)).rejects.toThrow("signature does not verify");
    });

    it("does not take that provider's tokens in an app that registered none", async () => {
      const { gate, external } = await gatekeeper();
      await expect(gate.admit("user_1", await external.sign(claims))).rejects.toThrow(SIGN_IN_REQUIRED);
    });
  });
});

describe("parseIdentitySettings", () => {
  it("keeps what is well formed and drops the rest", () => {
    expect(parseIdentitySettings({ google: ["a", 1, ""], apple: "x", external: { issuer: EXTERNAL, audience: 3 } })).toEqual({
      google: ["a"],
      apple: [],
      external: { issuer: EXTERNAL },
    });
    expect(parseIdentitySettings(undefined)).toEqual({ google: [], apple: [] });
    expect(parseIdentitySettings({ external: { audience: "a" } })).toEqual({ google: [], apple: [] });
  });

  it("never treats one of Cavos's own providers as the app's", () => {
    for (const issuer of [GOOGLE, "https://appleid.apple.com", "https://enclave.cavos.xyz/github"]) {
      expect(parseIdentitySettings({ external: { issuer } }).external).toBeUndefined();
    }
  });
});
