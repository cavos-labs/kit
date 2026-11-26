import { CavosAuth } from "./CavosAuth";
import { createSocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import { answerLogin, beginLogin, FIXTURE_APP_ID } from "./loginFixture";
import { loginNonceOf } from "./loginBinding";
import { WebCryptoLoginKey } from "./loginKey";

/**
 * `answerLogin` finishes a login with a given token, as the callback exchange
 * would. These tests lock in how its claims project onto an `Identity`,
 * especially the optional `name` claim (present on Google's id_token, absent on
 * the enclave-issued token used by email login).
 */

// Build a JWT-shaped string from an arbitrary claims object. Only the payload
// matters for `parseJwt`; header and signature are dummies.
function jwt(claims: Record<string, unknown>): string {
  const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.sig`;
}

describe("CavosAuth.handleCallback -> Identity", () => {
  afterEach(() => jest.restoreAllMocks());

  it("exchanges a one-time callback code without putting the JWT in the URL", async () => {
    const auth = new CavosAuth({ backendUrl: "https://cavos.test", appId: "app-id" });
    const token = jwt({
      iss: "https://accounts.google.com",
      sub: "code-user",
      nonce: await beginLogin(auth),
    });
    const fetchMock = jest.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ jwt: token }),
    } as Response);
    const id = await auth.handleCallback(
      `?cavos_auth_code=${"a".repeat(43)}`,
      "https://wallet.test/callback",
    );
    expect(id.userId).toBe("code-user");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://cavos.test/api/oauth/callback/exchange",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          code: "a".repeat(43),
          app_id: "app-id",
          redirect_uri: "https://wallet.test/callback",
        }),
      }),
    );
  });

  it("reads the standard OIDC `name` claim when present (Google id_token)", async () => {
    const auth = new CavosAuth();
    const id = await answerLogin(
      auth,
      jwt({
        nonce: await beginLogin(auth),
        iss: "https://accounts.google.com",
        sub: "google-user-123",
        email: "ada@example.com",
        name: "Ada Lovelace",
      }),
    );
    expect(id.userId).toBe("google-user-123");
    expect(id.email).toBe("ada@example.com");
    expect(id.name).toBe("Ada Lovelace");
    expect(id.provider).toBe("google");
  });

  it("yields name: undefined when the token has no `name` claim (enclave email token)", async () => {
    const auth = new CavosAuth();
    const id = await answerLogin(
      auth,
      jwt({
        iss: "https://enclave.cavos.xyz",
        sub: "email-subject-456",
        email: "anon@example.com",
        nonce: await beginLogin(auth),
        iat: 1_700_000_000,
        exp: 1_700_003_600,
      }),
    );
    expect(id.userId).toBe("email-subject-456");
    expect(id.email).toBe("anon@example.com");
    expect(id.name).toBeUndefined();
    expect(id.provider).toBe("email");
  });

  it("never reads a token from the callback URL", async () => {
    const auth = new CavosAuth();
    const token = jwt({ iss: "https://accounts.google.com", sub: "u", nonce: await beginLogin(auth) });
    for (const callback of [`?auth_data=${token}`, `?zk_auth_data=${token}`, token]) {
      await expect(auth.handleCallback(callback, "https://app.test/callback")).rejects.toThrow("no sign-in code");
    }
    expect(auth.getAuthToken()).toBeNull();
  });

  it("refuses a token from an issuer no login is bound to, signed or not", async () => {
    const auth = new CavosAuth();
    await beginLogin(auth);
    const forged = jwt({ iss: "https://attacker.example", sub: "victim-sub", email: "forged@attacker.example" });
    await expect(answerLogin(auth, forged)).rejects.toThrow("are not accepted");
    expect(auth.getAuthToken()).toBeNull();
  });

  it("keeps only an in-memory token fingerprint for one-session recovery binding", async () => {
    const auth = new CavosAuth();
    const nonce = await beginLogin(auth);
    const token = jwt({
      iss: "https://accounts.google.com",
      sub: "recent-user",
      nonce,
      iat: 1_700_000_000,
      exp: 1_700_003_600,
    });
    await answerLogin(auth, token);

    const credential = auth.consumeSocialRecoveryCredential();
    expect(credential).toMatchObject(createSocialRecoveryCredential(token));
    const key = await WebCryptoLoginKey.load("default");
    expect(nonce).toBe(`${FIXTURE_APP_ID}.${loginNonceOf(key!.publicKeyRaw())}`);
    // Still available after use, because a session holds a wallet on every
    // configured chain and each needs its own enrolment. Dropping it after the
    // first left the rest unprotected with nothing to try again with.
    //
    // Replay is refused where it can actually be enforced: the control plane
    // allows one session per credential per wallet, so this cannot be reused
    // against a wallet it has already enrolled. A one-shot here only ever
    // constrained a client that was cooperating anyway.
    expect(auth.consumeSocialRecoveryCredential()).toEqual(credential);
  });

  it("refuses a Google or Apple token that does not answer a login it started", async () => {
    const stranger = jwt({
      iss: "https://accounts.google.com",
      sub: "attacker",
      nonce: `${FIXTURE_APP_ID}.${"x".repeat(43)}`,
    });

    // No login in flight: a callback carrying someone else's code.
    const idle = new CavosAuth();
    await expect(answerLogin(idle, stranger)).rejects.toThrow("did not start here");
    expect(idle.getAuthToken()).toBeNull();

    // A login in flight, answered with a token minted for another one.
    const waiting = new CavosAuth();
    await beginLogin(waiting);
    await expect(answerLogin(waiting, stranger)).rejects.toThrow("does not match this sign-in");
    expect(() => waiting.getSocialRecoveryCredential()).toThrow();

    
    const nonce = await beginLogin(waiting);
    const mine = jwt({ iss: "https://appleid.apple.com", sub: "me", nonce });
    await expect(answerLogin(waiting, mine)).resolves.toMatchObject({ userId: "me" });
    await expect(answerLogin(waiting, mine)).rejects.toThrow("did not start here");
  });
});
