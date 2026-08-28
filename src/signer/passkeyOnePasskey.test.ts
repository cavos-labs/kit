import { describe, expect, it, jest, beforeEach } from "@jest/globals";
import { PasskeySigner } from "./PasskeySigner";
import { PRF_SALT } from "./prfSalt";

/**
 * One passkey per wallet, not one per chain.
 *
 * The approver credential and Stellar's PRF credential were two separate
 * `credentials.create()` calls: two prompts, and two passkeys in the user's
 * account for one wallet — with no way to tell which was which later.
 */
describe("enrolling a passkey", () => {
  const spki = new Uint8Array(91);
  // Uncompressed P-256 point at the tail of a DER SPKI header.
  spki.set([0x04], 26);
  const rawId = new Uint8Array([1, 2, 3, 4]);

  const credential = (prf?: ArrayBuffer) => ({
    rawId: rawId.buffer.slice(0),
    response: { getPublicKey: () => spki.buffer.slice(0) },
    getClientExtensionResults: () => (prf ? { prf: { results: { first: prf } } } : {}),
  });

  let create: ReturnType<typeof jest.fn>;

  beforeEach(() => {
    create = jest.fn(async () => credential());
    (globalThis as { window?: unknown }).window = { location: { hostname: "cavos.xyz" } };
    (globalThis as { navigator?: unknown }).navigator = { credentials: { create } };
    (globalThis as { crypto?: unknown }).crypto = {
      getRandomValues: (a: Uint8Array) => a,
    };
  });

  it("asks for the PRF secret while it creates the credential", async () => {
    // Stellar's factor comes from the same passkey or it is a second passkey.
    await new PasskeySigner().enroll({ userId: "u1", userName: "u@x.com" });

    const extensions = create.mock.calls[0][0].publicKey.extensions;
    expect(new Uint8Array(extensions.prf.eval.first)).toEqual(PRF_SALT);
  });

  it("returns the secret when the authenticator evaluated it", async () => {
    const secret = new Uint8Array(32).fill(7);
    create.mockResolvedValue(credential(secret.buffer.slice(0)));

    const enrolled = await new PasskeySigner().enroll({ userId: "u1", userName: "u@x.com" });

    expect(enrolled.secret).toEqual(secret);
  });

  it("returns no secret when the authenticator ignored PRF", async () => {
    // Common: PRF reports as enabled at creation and is evaluated only on an
    // assertion. Absent, not zeroed — a wrong secret would wrap a DEK nothing
    // can ever unwrap.
    const enrolled = await new PasskeySigner().enroll({ userId: "u1", userName: "u@x.com" });

    expect(enrolled.secret).toBeUndefined();
    expect(enrolled.credentialId).toEqual(rawId);
  });

  it("creates exactly one credential", async () => {
    await new PasskeySigner().enroll({ userId: "u1", userName: "u@x.com" });
    expect(create).toHaveBeenCalledTimes(1);
  });
});
