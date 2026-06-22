/** secp256r1 (P-256) public key of a device signer. */
export interface DevicePublicKey {
  x: bigint;
  y: bigint;
}

/** A raw secp256r1 signature over `sha256(tx_hash)`. */
export interface DeviceSignature {
  r: bigint;
  s: bigint;
  /** Recovery parity of the emitted (r, s); the contract normalizes high-s. */
  yParity: boolean;
}

/**
 * A silent, device-bound signer. The private key is a secp256r1 key generated
 * and kept on the device (non-extractable WebCrypto key on web, Secure Enclave
 * on native) — it never leaves the device and signs WITHOUT any user-visible
 * prompt (no passkey, no biometrics). OAuth / email only derive identity; they
 * are never involved in signing.
 *
 * `WebCryptoSigner` is the browser implementation. React Native and other
 * platforms provide their own implementation of this interface.
 */
export interface DeviceSigner {
  /** secp256r1 public key of this device signer. */
  getPublicKey(): Promise<DevicePublicKey>;

  /**
   * Sign a transaction hash silently. `txHash` is the 32-byte big-endian tx
   * hash; the signer signs `sha256(txHash)` and returns the raw (r, s, parity).
   */
  sign(txHash: Uint8Array): Promise<DeviceSignature>;
}
