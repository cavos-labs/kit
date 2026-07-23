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
  getSecret(): Promise<Uint8Array>;
}
