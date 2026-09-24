/**
 * How a device that is not a signer yet gets authorized.
 *
 * This is the app's decision, not something to discover at runtime. An app
 * either runs the enclave or it uses passkeys; mixing them means every user
 * gets whichever the SDK happened to find first, and the integrator cannot say
 * what their own product does.
 *
 * It used to be inferred — a passkey lookup, an enrolment lookup against the
 * backend, a priority ladder, a fallback to email when either had not answered
 * yet. That produced approval emails for wallets the enclave was about to
 * restore in seconds, because the ladder resolved before the lookups did.
 */

export type DeviceApproval =
  /** The attested enclave authorizes the device, given a fresh login proof. */
  | "enclave"
  /** A passkey on the device authorizes it, with one gesture. */
  | "passkey";

export type DeviceAuthorizationMethod =
  | "enclave"
  | "passkey"
  /**
   * The enclave route, without the proof it needs. That proof is never
   * persisted — it is what the enclave verifies — so it does not survive a
   * reload, and signing in again mints a new one. An action, not an error.
   */
  | "enclave-needs-login";

export interface DeviceAuthorizationInput {
  /** What the app chose. */
  approval: DeviceApproval;
  /** Whether a fresh login proof is available this session. */
  socialCredential: boolean;
  /**
   * Classic Stellar (`G…`) used to force passkey because Horizon extras the
   * enclave held could spend immediately. Native Ed25519 now unwraps a DEK
   * instead, so Stellar follows the app's approval method like Solana.
   */
  chain?: "starknet" | "solana" | "stellar";
}

export function resolveDeviceAuthorization(
  input: DeviceAuthorizationInput,
): DeviceAuthorizationMethod {
  if (input.approval === "passkey") return "passkey";
  return input.socialCredential ? "enclave" : "enclave-needs-login";
}

/**
 * How the built-in email provider signs in, given the app's approval method.
 *
 * An enclave-protected wallet is created and restored with a provider token
 * the enclave verifies. A Cavos email code yields none (Firebase has no native
 * OTP), so on the enclave the email link is the only email route that works.
 */
export function emailModeFor(
  method: DeviceAuthorizationMethod,
  requested: "magic-link" | "otp",
): "magic-link" | "otp" {
  return method === "passkey" ? requested : "magic-link";
}
