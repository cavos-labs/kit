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

/**
 * The environment having an enclave is not the same as this app using one.
 *
 * The recovery effects read the environment's flag alone, so an app that had
 * chosen passkeys still wrote enclave recovery authorities into its accounts —
 * and spent its one login credential doing it. Two methods running at once is
 * exactly what "the developer picks one" was meant to end.
 */
describe("which recovery machinery runs", () => {
  const enclaveRuns = (input: Parameters<typeof resolveDeviceAuthorization>[0]) =>
    resolveDeviceAuthorization(input) !== "passkey";

  it("does not run the enclave for an app on passkeys", () => {
    expect(enclaveRuns({ approval: "passkey", socialCredential: true })).toBe(false);
  });

  it("runs it for an app on the enclave", () => {
    expect(enclaveRuns({ approval: "enclave", socialCredential: true })).toBe(true);
  });

  it("still runs it when the login proof is missing, so it can ask for one", () => {
    expect(enclaveRuns({ approval: "enclave", socialCredential: false })).toBe(true);
  });
});
