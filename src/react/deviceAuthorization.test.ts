import { describe, expect, it } from "@jest/globals";
import { resolveDeviceAuthorization } from "./deviceAuthorization";

describe("how an unauthorized device gets in", () => {
  it("uses a passkey when there is one: instant, and nothing else is needed", () => {
    const { method } = resolveDeviceAuthorization({
      passkey: true,
      socialEnrolled: true,
      socialCredential: true,
    });
    expect(method).toBe("passkey");
  });

  it("uses the enclave when it is enrolled and the proof is in hand", () => {
    const { method } = resolveDeviceAuthorization({
      passkey: false,
      socialEnrolled: true,
      socialCredential: true,
    });
    expect(method).toBe("social");
  });

  it("asks for a fresh login rather than calling a missing proof an error", () => {
    // The proof is never persisted — it is what the enclave verifies — so it
    // does not survive a reload. Signing in again mints a new one, which makes
    // this a primary action, not a red message beside somebody else's spinner.
    const { method } = resolveDeviceAuthorization({
      passkey: false,
      socialEnrolled: true,
      socialCredential: false,
    });
    expect(method).toBe("social-needs-login");
  });

  it("falls back to email only when nothing automatic exists", () => {
    // Email was the default before: connect mailed one the moment it saw an
    // unauthorized device, even while the enclave was about to do it in
    // seconds. It needs a second device and the user's attention twice, so it
    // is the floor.
    const { method } = resolveDeviceAuthorization({
      passkey: false,
      socialEnrolled: false,
      socialCredential: false,
    });
    expect(method).toBe("email");
  });

  it("does not offer the enclave when the wallet has no authority on-chain", () => {
    const { method, alternatives } = resolveDeviceAuthorization({
      passkey: false,
      socialEnrolled: false,
      socialCredential: true,
    });
    expect(method).toBe("email");
    expect(alternatives).not.toContain("social");
  });

  it("keeps the rest as alternatives, never as things that also run", () => {
    const { method, alternatives } = resolveDeviceAuthorization({
      passkey: true,
      socialEnrolled: true,
      socialCredential: true,
    });
    expect(method).toBe("passkey");
    expect(alternatives).toEqual(["social", "email"]);
  });
});
