import { sha256 } from "@noble/hashes/sha256";
import type { PasskeyEnrollParams, PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { fromBase64, toBase64, utf8 } from "./encoding";
import { nativeModule } from "./NativeModule";

export interface NativePasskeyOptions {
  rpId: string;
  rpName?: string;
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
