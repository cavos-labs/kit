import { LocalDeviceUnwrapKey } from "../chains/stellar/DeviceUnwrapKey";
import { bytesToBase64Url } from "../crypto/encoding";
import type { SocialRecoveryCredential } from "./SocialRecoveryCredential";
import { generateMasterDEK, parseMasterDEK } from "../secret/dek";
import { wrapDekToSec1 } from "../secret/wrap";
import { toEnclaveDekPort } from "./EnclaveDekPort";
import type { SocialRecoveryClient } from "./SocialRecoveryClient";

const credential: SocialRecoveryCredential = {
  idToken: "a.b.c",
  tokenFingerprint: "fp",
  provider: "google",
};

describe("toEnclaveDekPort", () => {
  it("sends the DEK on enroll", async () => {
    const dek = generateMasterDEK();
    const enroll = jest.fn(async () => ({ sessionId: "s1", result: { result: "enrolled" } }));
    const port = toEnclaveDekPort({ enroll, recover: jest.fn() } as unknown as SocialRecoveryClient);
    await expect(port.enrollDek({ address: "Addr1", credential, dek })).resolves.toEqual({
      kind: "enrolled",
    });
    expect(enroll).toHaveBeenCalledWith({ walletAddress: "Addr1", credential, dek });
  });

  it("treats already_enrolled as recover", async () => {
    const dek = generateMasterDEK();
    const enroll = jest.fn(async () => {
      throw new Error('kit/social-recovery: /api/recovery/social/sessions -> 409 {"error":"already_enrolled","wallet_address":"AddrCanonical"}');
    });
    const port = toEnclaveDekPort({ enroll, recover: jest.fn() } as unknown as SocialRecoveryClient);
    await expect(port.enrollDek({ address: "Addr1", credential, dek })).resolves.toEqual({
      kind: "already-enrolled",
      address: "AddrCanonical",
    });
  });

  it("wraps the sealed DEK to this device and parses the blob", async () => {
    const dek = generateMasterDEK();
    const factor = LocalDeviceUnwrapKey.generate();
    const wrap = wrapDekToSec1(dek, factor.publicKeySec1());
    const recover = jest.fn(async (params: { authorizations?: unknown; recipientPublicSec1?: Uint8Array }) => {
      expect(params.authorizations).toEqual([]);
      expect(params.recipientPublicSec1).toEqual(factor.publicKeySec1());
      return {
        sessionId: "s2",
        result: { result: "recovered", stellar_device_wrap_b64: bytesToBase64Url(wrap) },
      };
    });
    const port = toEnclaveDekPort({ enroll: jest.fn(), recover } as unknown as SocialRecoveryClient);
    const got = await port.wrapDekToFactor({
      address: "Addr1",
      credential,
      recipientSec1: factor.publicKeySec1(),
    });
    expect(parseMasterDEK(await factor.unwrap(got))).toEqual(dek);
  });

  it("refuses a recover job that omitted the wrap", async () => {
    const recover = jest.fn(async () => ({
      sessionId: "s3",
      result: { result: "recovered" },
    }));
    const port = toEnclaveDekPort({ enroll: jest.fn(), recover } as unknown as SocialRecoveryClient);
    await expect(
      port.wrapDekToFactor({
        address: "Addr1",
        credential,
        recipientSec1: new Uint8Array(65),
      }),
    ).rejects.toThrow("enclave returned no device wrap");
  });

  it("looks up a sealed DEK enrollment by the token subject", async () => {
    const idToken = [
      Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url"),
      Buffer.from(JSON.stringify({ iss: "https://accounts.google.com", sub: "subject-1" })).toString(
        "base64url",
      ),
      "sig",
    ].join(".");
    const lookup = jest.fn(async () => ({ wallet_address: "AddrEnrolled" }));
    const port = toEnclaveDekPort({
      enroll: jest.fn(),
      recover: jest.fn(),
      lookupDekEnrollment: lookup,
    } as unknown as SocialRecoveryClient);
    await expect(
      port.lookupDek({
        credential: { idToken, tokenFingerprint: "fp", provider: "google" },
      }),
    ).resolves.toEqual({ address: "AddrEnrolled" });
    expect(lookup).toHaveBeenCalledWith({ provider: "google", subject: "subject-1" });
  });

  it("treats a rejected identity lookup as not enrolled", async () => {
    const idToken = [
      Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url"),
      Buffer.from(JSON.stringify({ iss: "https://accounts.google.com", sub: "subject-1" })).toString(
        "base64url",
      ),
      "sig",
    ].join(".");
    const port = toEnclaveDekPort({
      enroll: jest.fn(),
      recover: jest.fn(),
      lookupDekEnrollment: async () => {
        throw new Error(
          'kit/social-recovery: /api/recovery/social/enrollment -> 400 {"error":"app_id and wallet_address are required"}',
        );
      },
    } as unknown as SocialRecoveryClient);
    await expect(
      port.lookupDek({
        credential: { idToken, tokenFingerprint: "fp", provider: "google" },
      }),
    ).resolves.toBeNull();
  });
});
