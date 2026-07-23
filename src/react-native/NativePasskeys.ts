import { sha256 } from "@noble/hashes/sha256";
import type {
  EnrolledPasskey,
  PasskeyApprover,
  PasskeyEnrollParams,
  PasskeyPrfProvider,
} from "../signer/PasskeyProvider";
import type { PasskeyAssertion } from "../crypto/webauthn";
import { bytesToBigInt } from "../crypto/encoding";
import { derToRs } from "../crypto/webauthn";
import { base64url, decodeUtf8, fromBase64, toBase64, utf8 } from "./encoding";
import { nativeModule } from "./NativeModule";

export interface NativePasskeyOptions {
  rpId: string;
  rpName?: string;
}

export class NativePasskeySigner implements PasskeyApprover {
  constructor(private readonly opts: NativePasskeyOptions) {
    if (!opts.rpId) throw new Error("kit/native: rpId is required for passkeys");
  }

  async enroll(params: PasskeyEnrollParams): Promise<EnrolledPasskey> {
    const challenge = await randomBytes(32);
    const result = await nativeModule().createPasskey(JSON.stringify({
      rpId: this.opts.rpId,
      rpName: this.opts.rpName ?? this.opts.rpId,
      userId: toBase64(userHandle(params.userId)),
      userName: params.userName,
      displayName: params.displayName ?? params.userName,
      challenge: toBase64(challenge),
    }));
    const raw = fromBase64(result.publicKey);
    if (raw.length !== 65 || raw[0] !== 4) throw new Error("kit/native: invalid passkey public key");
    return {
      credentialId: fromBase64(result.credentialId),
      publicKey: {
        x: bytesToBigInt(raw.subarray(1, 33)),
        y: bytesToBigInt(raw.subarray(33, 65)),
      },
    };
  }

  async assert(challenge: Uint8Array): Promise<PasskeyAssertion> {
    const result = await nativeModule().getPasskey(JSON.stringify({
      rpId: this.opts.rpId,
      challenge: toBase64(challenge),
      userVerification: "preferred",
    }));
    const authenticatorData = fromBase64(result.authenticatorData);
    const clientDataJSON = fromBase64(result.clientDataJSON);
    const { r, s } = derToRs(fromBase64(result.signature));
    const offset = decodeUtf8(clientDataJSON).indexOf(base64url(challenge));
    if (offset < 0) throw new Error("kit/native: challenge missing from passkey client data");
    return { authenticatorData, clientDataJSON, r, s, challengeOffset: offset };
  }
}

const STELLAR_PRF_SALT = sha256(utf8("cavos-stellar-prf-v1"));

export class NativePasskeyPrf implements PasskeyPrfProvider {
  constructor(private readonly opts: NativePasskeyOptions) {
    if (!opts.rpId) throw new Error("kit/native: rpId is required for passkeys");
  }

  async enroll(params: PasskeyEnrollParams): Promise<{ credentialId: Uint8Array; secret?: Uint8Array }> {
    const result = await nativeModule().createPasskey(JSON.stringify({
      rpId: this.opts.rpId,
      rpName: this.opts.rpName ?? this.opts.rpId,
      userId: toBase64(userHandle(params.userId)),
      userName: params.userName,
      displayName: params.displayName ?? params.userName,
      challenge: toBase64(await randomBytes(32)),
      prfSalt: toBase64(STELLAR_PRF_SALT),
    }));
    return {
      credentialId: fromBase64(result.credentialId),
      ...(result.prfSecret ? { secret: fromBase64(result.prfSecret) } : {}),
    };
  }

  async getSecret(): Promise<Uint8Array> {
    const result = await nativeModule().getPasskey(JSON.stringify({
      rpId: this.opts.rpId,
      challenge: toBase64(await randomBytes(32)),
      userVerification: "required",
      prfSalt: toBase64(STELLAR_PRF_SALT),
    }));
    if (!result.prfSecret) {
      throw new Error("kit/native: passkey PRF is unsupported; use recovery code or another device");
    }
    return fromBase64(result.prfSecret);
  }
}

async function randomBytes(length: number): Promise<Uint8Array> {
  return fromBase64(await nativeModule().randomBytes(length));
}

function userHandle(userId: string): Uint8Array {
  const value = utf8(userId);
  return value.length <= 64 ? value : sha256(value);
}
