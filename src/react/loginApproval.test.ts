import { describe, expect, it } from "@jest/globals";
import { resolveDeviceAuthorization } from "./deviceAuthorization";

/**
 * When a new device gets authorized, per method.
 *
 * Asking during sign-in — for the enclave or a passkey — is the app's call,
 * not the SDK's. Login returns a session; `enrollPasskeyDefault` /
 * `approveDeviceWithPasskey` are what prompt WebAuthn, when the integrator
 * decides to.
 */
describe("the approval method is the app's choice", () => {
  const method = (input: Parameters<typeof resolveDeviceAuthorization>[0]) =>
    resolveDeviceAuthorization(input);

  it("names passkey when the app chose passkeys", () => {
    expect(method({ approval: "passkey", socialCredential: false })).toBe("passkey");
  });

  it("names enclave when the app runs the enclave", () => {
    expect(method({ approval: "enclave", socialCredential: true })).toBe("enclave");
  });

  it("names enclave on native Stellar", () => {
    expect(method({ approval: "enclave", socialCredential: true, chain: "stellar" })).toBe(
      "enclave",
    );
  });

  it("asks for a fresh sign-in when the enclave proof is missing", () => {
    expect(method({ approval: "enclave", socialCredential: false })).toBe("enclave-needs-login");
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

  it("runs it on native Stellar", () => {
    expect(
      enclaveRuns({ approval: "enclave", socialCredential: true, chain: "stellar" }),
    ).toBe(true);
  });

  it("still runs it when the login proof is missing, so it can ask for one", () => {
    expect(enclaveRuns({ approval: "enclave", socialCredential: false })).toBe(true);
  });
});
