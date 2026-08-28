/**
 * How this device gets authorized on a wallet it does not yet control.
 *
 * There are four ways in, and until now the choice between them was made in
 * three places at three different times: `Cavos.connect` mailed an approval the
 * moment it saw an unauthorized device, the social-recovery effect tried the
 * enclave separately, and the modal picked a screen from whichever flags those
 * two had set. Nobody decided, so all three ran, and the user got an approval
 * spinner, a recovery error and a recovery-phrase link on one screen.
 *
 * One decision, taken once, before anything is attempted. Nothing starts until
 * this names it.
 */

export type DeviceAuthorizationMethod =
  /** A passkey on this device authorizes it here and now. */
  | "passkey"
  /** The enclave can authorize it: enrolled, and the login proof is in hand. */
  | "social"
  /**
   * The enclave could authorize it, but the proof is gone. It is deliberately
   * never persisted — it is what the enclave verifies — so it does not survive
   * a reload. Signing in again mints a new one, which makes this a button
   * rather than an error.
   */
  | "social-needs-login"
  /** Nothing automatic is available: approve from a device that already has it. */
  | "email";

export interface DeviceAuthorizationCapabilities {
  /** A passkey is enrolled on the wallet AND this browser can use one. */
  passkey: boolean;
  /** The wallet has a recovery authority on-chain. */
  socialEnrolled: boolean;
  /** A fresh login proof is available this session. */
  socialCredential: boolean;
}

export interface DeviceAuthorization {
  method: DeviceAuthorizationMethod;
  /** The other ways in, for a "try another way" affordance. Never auto-run. */
  alternatives: DeviceAuthorizationMethod[];
}

const ORDER: DeviceAuthorizationMethod[] = ["passkey", "social", "social-needs-login", "email"];

/**
 * Ordered by what costs the user least.
 *
 * A passkey is instant and needs nothing but this device. The enclave is also
 * instant and needs no second device, but it spends a sponsored transaction and
 * waits out any configured timelock. Email needs another device and the user's
 * attention twice, so it is the floor rather than the default it became.
 */
export function resolveDeviceAuthorization(
  capabilities: DeviceAuthorizationCapabilities,
): DeviceAuthorization {
  const available: DeviceAuthorizationMethod[] = [];
  if (capabilities.passkey) available.push("passkey");
  if (capabilities.socialEnrolled) {
    available.push(capabilities.socialCredential ? "social" : "social-needs-login");
  }
  available.push("email");

  const method = ORDER.find((m) => available.includes(m)) ?? "email";
  return { method, alternatives: available.filter((m) => m !== method) };
}
