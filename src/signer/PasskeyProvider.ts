export interface PasskeyEnrollParams {
  userId: string;
  userName: string;
  displayName?: string;
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
