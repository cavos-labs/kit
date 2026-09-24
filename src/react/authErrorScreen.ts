/**
 * Where the auth modal goes when the provider reports a connect error, or
 * `null` to stay. The error has to land on a screen that shows it.
 */
export function screenForAuthError(input: {
  screen: string;
  needsDeviceApproval: boolean;
}): "select" | null {
  if (input.needsDeviceApproval && input.screen !== "device-approval") return "select";
  // The connecting spinner has no room for an error: left up, a failed
  // connect read as "taking longer than usual" forever.
  if (input.screen === "deploying") return "select";
  return null;
}
