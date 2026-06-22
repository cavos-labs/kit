import type { DevicePublicKey } from "../signer/DeviceSigner";

/**
 * Multi-device / recovery flow (roadmap §1.2). A new device requests addition;
 * the backend emails an approval prompt styled as a login request; the user
 * approves on an ALREADY-registered device, which signs `add_signer` for the
 * new pubkey. There is no legacy JWT path — recovery is purely device-signer
 * based.
 *
 * The backend lives outside this repo; this is the client contract the kit
 * speaks to. Provide an implementation (HTTP, etc.) when wiring an app.
 */
export interface RecoveryClient {
  /**
   * Step 1 (new device): request that this pubkey be added to the user's
   * account. Triggers the approval email. Returns a request id to poll.
   */
  requestDeviceAddition(params: {
    userId: string;
    accountAddress: string;
    newSigner: DevicePublicKey;
    /** Owner email to send the approval link to (the SDK has it from login). */
    email?: string;
    /** Optional device label (browser/UA) shown in the approval email. */
    deviceLabel?: string;
  }): Promise<{ requestId: string }>;

  /**
   * Step 3-4 (existing device): fetch a pending addition request so the
   * registered device can approve it by signing `add_signer`.
   */
  getPendingRequest(requestId: string): Promise<PendingDeviceRequest | null>;

  /** Mark a request approved after the `add_signer` tx is submitted. */
  confirmDeviceAddition(params: { requestId: string; txHash: string }): Promise<void>;
}

export interface PendingDeviceRequest {
  requestId: string;
  appId?: string;
  userId: string;
  accountAddress: string;
  newSigner: DevicePublicKey;
  createdAt: string;
  status: "pending" | "approved" | "expired";
}
