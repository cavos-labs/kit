import { describe, expect, it } from "@jest/globals";
import { decideSocialRecovery } from "./socialRecoveryDecision";

describe("when social recovery runs", () => {
  it("leaves an undeployed wallet alone", () => {
    // This device made it, so there is nothing to restore — and there is no
    // account on-chain yet to enrol an authority against.
    expect(decideSocialRecovery("undeployed", false)).toEqual({
      action: "skip",
      takesCredential: false,
    });
  });

  it("does not spend the credential on a wallet it skips", () => {
    // The bug that produced wallets nobody could recover. The credential is
    // one-shot, so taking it and returning leaves the enrolment that follows
    // the first execute with nothing, and it never happens — silently, with the
    // only symptom a second device failing weeks later.
    expect(decideSocialRecovery("undeployed", true).takesCredential).toBe(false);
    expect(decideSocialRecovery("ready", true).takesCredential).toBe(false);
  });

  it("never mistakes a brand-new wallet for one being recovered", () => {
    // `status !== 'ready' ? 'recover' : 'enroll'` read every undeployed wallet
    // as a restore, and told the integrator to enable a feature already on.
    expect(decideSocialRecovery("undeployed", false).action).not.toBe("recover");
  });

  it("enrols a deployed wallet with no authority yet", () => {
    expect(decideSocialRecovery("ready", false)).toEqual({
      action: "enroll",
      takesCredential: true,
    });
  });

  it("does not re-enrol one that already has an authority", () => {
    // The enclave would only answer 409, and the UI flashed "securing recovery"
    // on every login to find that out.
    expect(decideSocialRecovery("ready", true).action).toBe("skip");
  });

  it("recovers on a device that is not a signer yet", () => {
    expect(decideSocialRecovery("needs-device-approval", false)).toEqual({
      action: "recover",
      takesCredential: true,
    });
  });

  it("still recovers a device even when the wallet is enrolled", () => {
    // `alreadyEnrolled` gates enrolment, not recovery — an enrolled wallet is
    // precisely the one a new device can restore.
    expect(decideSocialRecovery("needs-device-approval", true).action).toBe("recover");
  });
});
