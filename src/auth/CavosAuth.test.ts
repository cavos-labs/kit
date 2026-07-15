import { CavosAuth } from "./CavosAuth";

/**
 * `handleCallback(authData)` is the pure, network-free seam into
 * `identityFromAuthData` — it only base64-decodes the JWT payload and projects
 * claims onto an `Identity`. These tests lock in that projection, especially
 * the optional `name` claim (present on Google's id_token, absent on the
 * Cavos-signed Firebase JWT used by email/OTP/magic-link).
 */

// Build a JWT-shaped string from an arbitrary claims object. Only the payload
// matters for `parseJwt`; header and signature are dummies.
function jwt(claims: Record<string, unknown>): string {
  const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.sig`;
}

describe("CavosAuth.handleCallback -> Identity", () => {
  it("reads the standard OIDC `name` claim when present (Google id_token)", async () => {
    const auth = new CavosAuth();
    const id = await auth.handleCallback(
      jwt({
        sub: "google-user-123",
        email: "ada@example.com",
        name: "Ada Lovelace",
        firebase: { sign_in_provider: "google.com" },
      }),
    );
    expect(id.userId).toBe("google-user-123");
    expect(id.email).toBe("ada@example.com");
    expect(id.name).toBe("Ada Lovelace");
    expect(id.provider).toBe("google.com");
  });

  it("yields name: undefined when the token has no `name` claim (Cavos Firebase JWT)", async () => {
    // Mirrors the 5-field payload cavos-web/lib/firebase-jwt.ts actually mints
    // for email/OTP/magic-link — no `name`.
    const auth = new CavosAuth();
    const id = await auth.handleCallback(
      jwt({
        sub: "firebase-uid-456",
        email: "anon@example.com",
        nonce: "n-0",
        iat: 1_700_000_000,
        exp: 1_700_003_600,
        firebase: { sign_in_provider: "password" },
      }),
    );
    expect(id.userId).toBe("firebase-uid-456");
    expect(id.email).toBe("anon@example.com");
    expect(id.name).toBeUndefined();
    expect(id.provider).toBe("password");
  });

  it("accepts ?auth_data=<jwt> callback strings", async () => {
    const auth = new CavosAuth();
    const token = jwt({ sub: "u", name: "From URL" });
    const id = await auth.handleCallback(`?auth_data=${token}`);
    expect(id.userId).toBe("u");
    expect(id.name).toBe("From URL");
  });
});
