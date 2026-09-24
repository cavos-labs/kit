import { PasskeyPrf } from "../chains/stellar/PasskeyPrf";
import { POPUP_READY, POPUP_RESULT, type PopupIntent, type PopupResult } from "./protocol";
import { button, el, setEnabled, sheet, type Sheet } from "./ui";

export interface VaultConfirmOptions {
  /** Name shown in the passkey prompt. */
  rpName?: string;
}

type Secret = Extract<PopupResult, { secret: Uint8Array }>;
type PasskeyIntent = Extract<PopupIntent, { kind: "passkey" }>;

/** The Cavos window the vault iframe opens for passkeys some browsers refuse inside a frame. */
export function startVaultConfirm(opts: VaultConfirmOptions = {}): void {
  document.body.style.margin = "0";
  const opener = window.opener as Window | null;
  if (!opener) {
    const view = sheet({ overlay: false });
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
    if (intent?.kind === "passkey") showPasskey(sheet({ overlay: false }), intent, opts.rpName ?? "Cavos", send);
  });
  opener.postMessage({ type: POPUP_READY }, location.origin);
}

function showPasskey(view: Sheet, intent: PasskeyIntent, rpName: string, send: (result: PopupResult) => void): void {
  const passkeys = new PasskeyPrf({ rpName });
  view.title.textContent = intent.create ? "Add a passkey" : "Verify it's you";
  const message = el("span", {}, intent.create ? "Create a passkey to continue." : "Use your passkey to continue.");
  view.body.replaceChildren(message);

  const use = button("Use passkey", "primary");
  const create = button("Create passkey", "primary");
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
  view.actions.replaceChildren(intent.create ? create : use);
}
