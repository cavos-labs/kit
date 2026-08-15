import {
  createSocialRecoveryCredential,
  socialRecoveryProvider,
} from "./SocialRecoveryCredential";

/** An unsigned token carrying `claims`. Nothing here verifies signatures. */
function token(claims: Record<string, unknown>): string {
  const part = (value: unknown) =>
    Buffer.from(JSON.stringify(value))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${part({ alg: "RS256" })}.${part(claims)}.signature`;
}

describe("socialRecoveryProvider", () => {
  it("reads each provider from its issuer", () => {
    expect(socialRecoveryProvider(token({ iss: "https://accounts.google.com" }))).toBe("google");
    expect(socialRecoveryProvider(token({ iss: "accounts.google.com" }))).toBe("google");
    expect(socialRecoveryProvider(token({ iss: "https://appleid.apple.com" }))).toBe("apple");
    expect(
      socialRecoveryProvider(token({ iss: "https://securetoken.google.com/cavos-prod" })),
    ).toBe("email");
  });

  it("separates Firebase from plain Google, which share a domain", () => {
    // Both are Google-operated and the prefixes are similar enough to swap by
    // accident, but they are different issuers with different JWKS, so a
    // mix-up would build a policy the token cannot verify against.
    const firebase = socialRecoveryProvider(
      token({ iss: "https://securetoken.google.com/project-1" }),
    );
    const google = socialRecoveryProvider(token({ iss: "https://accounts.google.com" }));
    expect(firebase).toBe("email");
    expect(google).toBe("google");
  });

  it("refuses an issuer no provider in the policy set uses", () => {
    expect(() => socialRecoveryProvider(token({ iss: "https://evil.example" }))).toThrow(
      /no social recovery provider/,
    );
    // A near-miss on the trusted host must not pass either.
    expect(() =>
      socialRecoveryProvider(token({ iss: "https://accounts.google.com.evil.example" })),
    ).toThrow(/no social recovery provider/);
  });

  it("refuses a token with no issuer at all", () => {
    expect(() => socialRecoveryProvider(token({ sub: "user-1" }))).toThrow(
      /no social recovery provider/,
    );
  });

  it("refuses a malformed token rather than guessing", () => {
    expect(() => socialRecoveryProvider("not-a-token")).toThrow(/malformed/);
    expect(() => socialRecoveryProvider("a.!!!not-base64!!!.c")).toThrow(/malformed/);
  });
});

describe("createSocialRecoveryCredential", () => {
  it("carries the provider alongside the fingerprint", () => {
    const idToken = token({ iss: "https://appleid.apple.com", sub: "001550.abc" });
    const credential = createSocialRecoveryCredential(idToken);
    expect(credential.provider).toBe("apple");
    expect(credential.idToken).toBe(idToken);
    expect(credential.tokenFingerprint).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("fingerprints distinct tokens distinctly", () => {
    const a = createSocialRecoveryCredential(token({ iss: "https://accounts.google.com", sub: "1" }));
    const b = createSocialRecoveryCredential(token({ iss: "https://accounts.google.com", sub: "2" }));
    expect(a.tokenFingerprint).not.toBe(b.tokenFingerprint);
  });

  it("rejects a credential from an issuer the enclave will not verify", () => {
    expect(() => createSocialRecoveryCredential(token({ iss: "https://evil.example" }))).toThrow();
  });
});
