import { describe, expect, it } from "@jest/globals";
import { resolveDeviceAuthorization } from "./deviceAuthorization";

describe("how a new device gets authorized", () => {
  it("uses passkeys when the app chose passkeys", () => {
    expect(resolveDeviceAuthorization({ approval: "passkey", socialCredential: false })).toBe(
      "passkey",
    );
  });

  it("does not care about the login proof when the app chose passkeys", () => {
    // The proof is the enclave's business. An app on passkeys never touches it,
    // so its absence must not change anything.
    expect(resolveDeviceAuthorization({ approval: "passkey", socialCredential: true })).toBe(
      "passkey",
    );
  });

  it("uses the enclave when the app chose the enclave", () => {
    expect(resolveDeviceAuthorization({ approval: "enclave", socialCredential: true })).toBe(
      "enclave",
    );
  });

  it("asks for a fresh sign-in when the enclave's proof is gone", () => {
    // Never an error and never a silent fallback to something else: the app
    // chose the enclave, so the answer is the one thing that makes the enclave
    // usable again.
    expect(resolveDeviceAuthorization({ approval: "enclave", socialCredential: false })).toBe(
      "enclave-needs-login",
    );
  });

  it("never resolves to a route the app did not choose", () => {
    // The old ladder could mail an approval for a wallet the enclave was about
    // to restore, because it resolved before the lookups it depended on.
    const everyInput = [true, false].flatMap((socialCredential) =>
      (["enclave", "passkey"] as const).map((approval) =>
        resolveDeviceAuthorization({ approval, socialCredential }),
      ),
    );
    expect(everyInput).not.toContain("email");
  });
});
