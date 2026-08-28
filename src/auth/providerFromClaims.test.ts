import { describe, expect, it } from "@jest/globals";
import { CavosAuth } from "./CavosAuth";

/**
 * `user.provider` is public API and the UI names it back to the user
 * ("Connected with Google"). A raw Google or Apple id_token carries neither
 * `provider` nor Firebase's `sign_in_provider`, so this used to resolve to the
 * literal "oauth" — true, and useless to say out loud.
 */
function identityFrom(claims: Record<string, unknown>): Promise<{ provider?: string }> {
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const token = `e30.${payload}.sig`;
  // `identityFromAuthData` is private; the OAuth callback is its only entry
  // point that takes raw auth data, which is exactly the path under test.
  const auth = new CavosAuth();
  return (auth as unknown as {
    identityFromAuthData: (data: string, provider: string) => Promise<{ provider?: string }>;
  }).identityFromAuthData(JSON.stringify({ jwt: token }), "oauth");
}

describe("provider from the credential", () => {
  it("names Google from its issuer", async () => {
    const id = await identityFrom({ iss: "https://accounts.google.com", sub: "u1" });
    expect(id.provider).toBe("google");
  });

  it("names Apple from its issuer", async () => {
    const id = await identityFrom({ iss: "https://appleid.apple.com", sub: "u1" });
    expect(id.provider).toBe("apple");
  });

  it("calls the Cavos-signed email token email, not firebase", async () => {
    const id = await identityFrom({ iss: "https://cavos.app/firebase", sub: "u1" });
    expect(id.provider).toBe("email");
  });

  it("passes Firebase's own sign-in provider through unchanged", async () => {
    // Already public API — callers switch on "google.com", so normalising it
    // here would be a silent breaking change. Display code normalises instead.
    const id = await identityFrom({
      iss: "https://securetoken.google.com/x",
      sub: "u1",
      firebase: { sign_in_provider: "google.com" },
    });
    expect(id.provider).toBe("google.com");
  });

  it("falls back rather than inventing a provider it cannot know", async () => {
    const id = await identityFrom({ iss: "https://example.test", sub: "u1" });
    expect(id.provider).toBe("oauth");
  });
});
