import { describe, expect, it } from "@jest/globals";
import { CavosAuth } from "./CavosAuth";
import { beginLogin } from "./loginFixture";
import { requiresLoginBinding } from "./loginBinding";

/**
 * `user.provider` is public API and the UI names it back to the user
 * ("Connected with Google"). A raw Google or Apple id_token carries no
 * `provider` claim, so this used to resolve to the
 * literal "oauth" — true, and useless to say out loud.
 */
async function identityFrom(claims: Record<string, unknown>): Promise<{ provider?: string }> {
  const auth = new CavosAuth();
  // A Google or Apple token is only accepted as the answer to a login.
  const nonce = requiresLoginBinding(claims.iss) ? await beginLogin(auth) : undefined;
  const payload = Buffer.from(JSON.stringify({ ...claims, nonce })).toString("base64url");
  const token = `e30.${payload}.sig`;
  // `identityFromAuthData` is private; the OAuth callback is its only entry
  // point that takes raw auth data, which is exactly the path under test.
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

  it("names the enclave's email token email", async () => {
    const id = await identityFrom({ iss: "https://enclave.cavos.xyz", sub: "u1" });
    expect(id.provider).toBe("email");
  });

  it("falls back rather than inventing a provider it cannot know", async () => {
    const id = await identityFrom({ iss: "https://example.test", sub: "u1" });
    expect(id.provider).toBe("oauth");
  });
});
