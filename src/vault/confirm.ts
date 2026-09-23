import { PasskeyPrf } from "../chains/stellar/PasskeyPrf";
import { POPUP_READY, POPUP_RESULT, type PopupIntent, type PopupResult } from "./protocol";
import { renderReview } from "./review";
import { armableButton, button, el, setEnabled, sheet, type Sheet } from "./ui";

/** Same pause as in the frame, so a click already under way cannot approve. */
const ARM_MS = 700;

export interface VaultConfirmOptions {
  /** Name shown in the passkey prompt. */
  rpName?: string;
}

type Secret = Extract<PopupResult, { secret: Uint8Array }>;
type PasskeyIntent = Extract<PopupIntent, { kind: "passkey" }>;

/** The Cavos window the vault iframe opens for passkeys and, where it must, approvals. */
export function startVaultConfirm(opts: VaultConfirmOptions = {}): void {
  document.body.style.margin = "0";
  const view = sheet({ overlay: false });
  const opener = window.opener as Window | null;
  if (!opener) {
    view.title.textContent = "Nothing to do here";
    view.body.textContent = "This window opens from an app when Cavos needs you.";
    return;
  }

  const send = (result: PopupResult) => {
    opener.postMessage({ type: POPUP_RESULT, result }, location.origin);
    window.close();
  };

  window.addEventListener("message", (event: MessageEvent<PopupIntent>) => {
    if (event.source !== opener || event.origin !== location.origin) return;
    const intent = event.data;
    if (intent?.kind === "passkey") showPasskey(view, intent, opts.rpName ?? "Cavos", send);
    if (intent?.kind === "review") showReview(view, intent, send);
  });
  opener.postMessage({ type: POPUP_READY }, location.origin);
}

function showReview(
  view: Sheet,
  intent: Extract<PopupIntent, { kind: "review" }>,
  send: (result: PopupResult) => void,
): void {
  renderReview(view, intent.lines, intent.network, intent.app);
  const approve = armableButton("Approve");
  const reject = button("Reject", "secondary");
  approve.node.onclick = () => send({ approved: true });
  reject.onclick = () => send({ approved: false });
  view.actions.replaceChildren(approve.node, reject);
  approve.arm(ARM_MS);
}

function showPasskey(view: Sheet, intent: PasskeyIntent, rpName: string, send: (result: PopupResult) => void): void {
  const passkeys = new PasskeyPrf({ rpName });
  view.title.textContent = "Unlock your wallet";
  const message = el("span", {}, "Use your passkey to continue.");
  view.body.replaceChildren(message);

  const use = button("Use passkey", "primary");
  const create = button("Create a passkey", "secondary");
  const busy = (on: boolean) => [use, create].forEach((b) => setEnabled(b, !on));
  const attempt = async (run: () => Promise<Secret | null>) => {
    busy(true);
    try {
      const result = await run();
      if (result) send(result);
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "The passkey did not respond.";
    }
    busy(false);
  };

  use.onclick = () =>
    attempt(async () => ({ secret: await passkeys.getSecret(intent.credentialId), credentialId: intent.credentialId }));
  create.onclick = () =>
    attempt(async () => {
      const enrolled = await passkeys.enroll({ userId: intent.userId, userName: intent.userName });
      if (enrolled.secret) return { secret: enrolled.secret, credentialId: enrolled.credentialId };
      // Many authenticators create the credential without evaluating PRF.
      message.textContent = "Passkey created. Confirm it once more.";
      intent = { ...intent, credentialId: enrolled.credentialId };
      view.actions.replaceChildren(use);
      return null;
    });
  view.actions.replaceChildren(use, create);
}
