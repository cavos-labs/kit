import { CavosAuth } from "./CavosAuth";

/**
 * Accepting a provider token from the host's own login.
 *
 * The real verification happens inside the enclave, against the issuer and
 * audience sealed for the app — these cover the gate in front of it, which
 * exists so an obvious mistake reads as a clear error instead of an opaque
 * enclave rejection minutes later.
 */
function jwt(claims: Record<string, unknown>): string {
  const part = (o: unknown) =>
    Buffer.from(JSON.stringify(o))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${part({ alg: "RS256" })}.${part(claims)}.${part("signature")}`;
}

const auth = () => new CavosAuth({ appId: "app-1" });

describe("useExternalSocialRecoveryToken", () => {
  it("accepts a Google token", () => {
    const a = auth();
    a.useExternalSocialRecoveryToken(jwt({ iss: "https://accounts.google.com", sub: "u1" }));
    expect(a.consumeSocialRecoveryCredential().tokenFingerprint).toEqual(expect.any(String));
  });

  it("accepts an Apple token", () => {
    const a = auth();
    expect(() =>
      a.useExternalSocialRecoveryToken(jwt({ iss: "https://appleid.apple.com", sub: "u1" })),
    ).not.toThrow();
  });

  it("accepts a Firebase token", () => {
    const a = auth();
    expect(() =>
      a.useExternalSocialRecoveryToken(
        jwt({ iss: "https://securetoken.google.com/some-project", sub: "u1" }),
      ),
    ).not.toThrow();
  });

  it("rejects the host's own session JWT", () => {
    // The likeliest mistake: passing the Clerk/Auth0 token rather than the
    // provider id_token underneath it. Nothing signed by them can be verified
    // against a provider's keys, so say so plainly.
    const a = auth();
    expect(() =>
      a.useExternalSocialRecoveryToken(jwt({ iss: "https://clerk.example.com", sub: "u1" })),
    ).toThrow(/cannot be used for social recovery/);
  });

  it("rejects a token with no issuer", () => {
    const a = auth();
    expect(() => a.useExternalSocialRecoveryToken(jwt({ sub: "u1" }))).toThrow();
  });

  it("rejects a lookalike issuer", () => {
    // Substring matching here would accept an attacker-controlled host.
    const a = auth();
    for (const iss of [
      "https://accounts.google.com.evil.test",
      "https://evil.test/https://accounts.google.com",
      "https://securetoken.google.com.evil.test/p",
    ]) {
      expect(() => a.useExternalSocialRecoveryToken(jwt({ iss, sub: "u1" }))).toThrow();
    }
  });

  it("leaves no credential behind when the token is rejected", () => {
    const a = auth();
    expect(() =>
      a.useExternalSocialRecoveryToken(jwt({ iss: "https://clerk.example.com" })),
    ).toThrow();
    expect(() => a.consumeSocialRecoveryCredential()).toThrow();
  });

  it("hands out the credential exactly once", () => {
    // A provider token is bound to one enclave session; retaining it after use
    // would only enable an accidental replay.
    const a = auth();
    a.useExternalSocialRecoveryToken(jwt({ iss: "https://accounts.google.com", sub: "u1" }));
    expect(a.consumeSocialRecoveryCredential()).toBeTruthy();
    expect(() => a.consumeSocialRecoveryCredential()).toThrow();
  });
});
