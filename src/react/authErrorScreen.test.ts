import { describe, expect, it } from "@jest/globals";
import { screenForAuthError } from "./authErrorScreen";
import { emailModeFor } from "./deviceAuthorization";

describe("a connect error lands where it can be read", () => {
  it("leaves the connecting spinner, which cannot show it", () => {
    expect(screenForAuthError({ screen: "deploying", needsDeviceApproval: false })).toBe("select");
  });

  it("returns to sign-in for a device that still needs approval", () => {
    expect(screenForAuthError({ screen: "deploying", needsDeviceApproval: true })).toBe("select");
  });

  it("keeps the approval screen, which owns its own errors", () => {
    expect(screenForAuthError({ screen: "device-approval", needsDeviceApproval: true })).toBeNull();
  });

  it("stays on a screen that already shows errors", () => {
    expect(screenForAuthError({ screen: "magic-link", needsDeviceApproval: false })).toBeNull();
  });
});

describe("email signs in the way the app's recovery can use", () => {
  it("keeps the app's choice on passkeys", () => {
    expect(emailModeFor("passkey", "otp")).toBe("otp");
  });

  it("uses the email link on the enclave, where a code yields no token", () => {
    expect(emailModeFor("enclave", "otp")).toBe("magic-link");
    expect(emailModeFor("enclave-needs-login", "otp")).toBe("magic-link");
  });
});
