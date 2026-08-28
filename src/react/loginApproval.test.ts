import { describe, expect, it } from "@jest/globals";
import { resolveDeviceAuthorization } from "./deviceAuthorization";

/**
 * When a new device gets authorized, per method.
 *
 * Authorization was moved off the login deliberately: the enclave takes
 * seconds, can fail, and asking during sign-in broke onboarding for a wallet
 * the user could otherwise already see. A passkey has none of that — local,
 * instant, and the gesture is the one the user already associates with proving
 * it is them — so waiting buys nothing and leaves a session that cannot sign.
 */
describe("asking at login", () => {
  const asksAtLogin = (input: Parameters<typeof resolveDeviceAuthorization>[0]) =>
    resolveDeviceAuthorization(input) === "passkey";

  it("asks when the app chose passkeys", () => {
    expect(asksAtLogin({ approval: "passkey", socialCredential: false })).toBe(true);
  });

  it("does not ask when the app runs the enclave", () => {
    // The reason the login was left alone in the first place.
    expect(asksAtLogin({ approval: "enclave", socialCredential: true })).toBe(false);
  });

  it("does not ask when the enclave is waiting on a fresh sign-in", () => {
    expect(asksAtLogin({ approval: "enclave", socialCredential: false })).toBe(false);
  });
});
