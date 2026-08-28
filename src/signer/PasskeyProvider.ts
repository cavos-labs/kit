import type { DevicePublicKey } from "./DeviceSigner";
import type { PasskeyAssertion } from "../crypto/webauthn";

export interface PasskeyEnrollParams {
  userId: string;
  userName: string;
  displayName?: string;
}

export interface EnrolledPasskey {
  publicKey: DevicePublicKey;
  credentialId: Uint8Array;
  /**
   * The PRF secret, when the authenticator returned one at creation. It is the
   * Stellar DEK factor, so one passkey covers every chain. Many authenticators
   * report PRF as enabled at creation without evaluating it, so callers must be
   * ready to ask for it with an assertion on this same credential.
   */
  secret?: Uint8Array;
}

/** Runtime-neutral passkey contract used by Starknet and Solana approvals. */
export interface PasskeyApprover {
  enroll(params: PasskeyEnrollParams): Promise<EnrolledPasskey>;
  assert(challenge: Uint8Array): Promise<PasskeyAssertion>;
}

export interface PasskeyPrfEnrollResult {
  credentialId: Uint8Array;
  secret?: Uint8Array;
}

/** Runtime-neutral PRF contract used by the Stellar envelope factor. */
export interface PasskeyPrfProvider {
  enroll(params: PasskeyEnrollParams): Promise<PasskeyPrfEnrollResult>;
  getSecret(credentialId?: Uint8Array): Promise<Uint8Array>;
}
