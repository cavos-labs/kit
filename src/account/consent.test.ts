import { ed25519 } from "@noble/curves/ed25519";
import { ec, hash } from "starknet";
import { starknetAddressFromPublicKey } from "../chains/starknet/keys";
import { bytesToBase64Url, utf8ToBytes } from "../crypto/encoding";
import { generateMasterDEK, parseMasterDEK } from "../secret/dek";
import { nativeAddress, parseAppSalt } from "../secret/derive";
import { PublicKey } from "@solana/web3.js";
import { consentAction, consentMessage, signConsent } from "./consent";

const SALT = "salt";

function challenge(payload: Record<string, unknown>): string {
  return `v1.${bytesToBase64Url(utf8ToBytes(JSON.stringify(payload)))}.sig`;
}

const valid = { kind: "end_user_consent", app_id: "a", environment_id: "e", sub: "u", state: "s", issued_at: 1 };

describe("consent", () => {
  it("frames the message with the challenge length", () => {
    expect(consentMessage("abc")).toBe("Cavos Consent:\n3\nabc");
  });

  it("reads the action of a challenge", () => {
    expect(consentAction(challenge({ ...valid, action: "delete_account" }))).toBe("delete_account");
    expect(consentAction(challenge({ ...valid, action: "disable_recovery" }))).toBe("disable_recovery");
    expect(consentAction(challenge({ ...valid, action: "enable_recovery" }))).toBe("enable_recovery");
  });

  it("rejects anything that is not a consent challenge", () => {
    expect(() => consentAction("abc")).toThrow("not a consent challenge");
    expect(() => consentAction("v2.e30.sig")).toThrow("not a consent challenge");
    expect(() => consentAction("v1.!!.sig")).toThrow("not a consent challenge");
    expect(() => consentAction(challenge({ ...valid, kind: "other", action: "delete_account" }))).toThrow(
      "not a consent challenge",
    );
    expect(() => consentAction(challenge({ ...valid, action: "wipe" }))).toThrow("not a consent challenge");
  });

  it.each(["solana", "stellar"] as const)("signs with the %s Ed25519 key", (chain) => {
    const bytes = generateMasterDEK();
    const text = challenge({ ...valid, action: "delete_account" });
    const proof = signConsent(parseMasterDEK(bytes), chain, SALT, text);
    expect(proof.chain).toBe(chain);
    expect(proof.public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(proof.signature).toHaveLength(1);
    const publicKey = Buffer.from(proof.public_key, "hex");
    expect(ed25519.verify(Buffer.from(proof.signature[0], "hex"), utf8ToBytes(consentMessage(text)), publicKey)).toBe(true);
    if (chain === "solana") {
      expect(new PublicKey(publicKey).toBase58()).toBe(nativeAddress(bytes, "solana", parseAppSalt(SALT)));
    }
  });

  it("signs with the Starknet key", () => {
    const bytes = generateMasterDEK();
    const text = challenge({ ...valid, action: "disable_recovery" });
    const proof = signConsent(parseMasterDEK(bytes), "starknet", SALT, text);
    expect(proof.chain).toBe("starknet");
    expect(proof.public_key).toMatch(/^04[0-9a-f]{128}$/);
    const compact = proof.signature.map((value) => BigInt(value).toString(16).padStart(64, "0")).join("");
    const digest = hash.starknetKeccak(consentMessage(text)).toString(16).padStart(64, "0");
    expect(ec.starkCurve.verify(compact, digest, proof.public_key)).toBe(true);
    const x = proof.public_key.slice(2, 66);
    expect(starknetAddressFromPublicKey(`0x${x}`)).toBe(nativeAddress(bytes, "starknet", parseAppSalt(SALT)));
  });

  it("zeroizes the DEK it was given", () => {
    const dek = generateMasterDEK();
    signConsent(dek, "solana", SALT, challenge({ ...valid, action: "delete_account" }));
    expect(dek.every((byte) => byte === 0)).toBe(true);
  });
});
