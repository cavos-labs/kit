import type { ConsentAction } from "../account/consent";
import { PasskeyPrf } from "../chains/stellar/PasskeyPrf";
import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { POPUP_READY, POPUP_RESULT, type PopupIntent, type PopupResult } from "./protocol";
import type { Line } from "./policy";
import { canTrackVisibility, hostOf, renderReview } from "./review";
import { armableButton, button, el, setEnabled, sheet, type Armable, type Sheet } from "./ui";

/** Approve fills in over this long once the modal is seen, so a click aimed at something else cannot land on it. */
const ARM_MS = 700;

const CONSENT_COPY: Record<ConsentAction, { title: string; body: string; confirm: string }> = {
  delete_account: {
    title: "Delete your account",
    body: "This removes your account from this app: your wallet registration, devices, passkey backup and recovery. Your wallet stays on the blockchain with its funds. If no other device holds its key, you will lose access to those funds for good.",
    confirm: "Delete account",
  },
  disable_recovery: {
    title: "Turn off recovery by sign-in",
    body: "Cavos will stop holding a recovery copy of your key. If you lose this device and have no passkey, you lose this wallet.",
    confirm: "Turn off",
  },
  enable_recovery: {
    title: "Turn on recovery by sign-in",
    body: "Cavos will keep a recovery copy of your key, sealed in its recovery enclave, the next time you sign in.",
    confirm: "Turn on",
  },
};

type Secret = { secret: Uint8Array; credentialId?: Uint8Array };

/** The vault's own UI, drawn inside its iframe over the embedding app. */
export class VaultModal {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly origin: string,
    private readonly confirmUrl: string,
    private readonly setVisible: (visible: boolean) => void,
  ) {}

  review(lines: Line[], network: string): Promise<boolean> {
    return this.serial(() => this.showReview(lines, network));
  }

  consent(action: ConsentAction): Promise<boolean> {
    return this.serial(() => this.showConsent(action));
  }

  passkey(user: { userId: string; userName: string }): PasskeyPrfProvider {
    return {
      enroll: async () => {
        const { secret, credentialId } = await this.serial(() => this.showPasskey(user, { create: true }));
        if (!credentialId) throw new Error("kit/vault: the new passkey has no credential id");
        return { credentialId, secret };
      },
      getSecret: async (credentialId) =>
        (await this.serial(() => this.showPasskey(user, { create: false, credentialId }))).secret,
    };
  }

  private serial<T>(show: () => Promise<T>): Promise<T> {
    const run = this.queue.then(show);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async open(): Promise<Sheet> {
    this.setVisible(true);
    await viewportReady();
    return sheet({ overlay: true });
  }

  private async dismiss(view: Sheet): Promise<void> {
    await view.close();
    this.setVisible(false);
  }

  private async showReview(lines: Line[], network: string): Promise<boolean> {
    const view = await this.open();
    renderReview(view, lines, network, hostOf(this.origin));
    return new Promise((resolve) => {
      const reject = button("Reject", "secondary");
      let settled = false;
      let unguard = () => {};
      const finish = async (approved: boolean) => {
        if (settled) return;
        settled = true;
        unguard();
        document.removeEventListener("keydown", onKey);
        await this.dismiss(view);
        resolve(approved);
      };
      const onKey = (event: KeyboardEvent) => {
        if (event.key === "Escape") void finish(false);
      };
      document.addEventListener("keydown", onKey);
      reject.onclick = () => void finish(false);

      const approve = armableButton("Approve");
      view.actions.append(approve.node, reject);
      approve.node.onclick = () => void finish(true);
      // Where the browser can tell (Intersection Observer v2), Approve arms only
      // while the page is not covering or fading the frame. Elsewhere (Safari)
      // it cannot, and the arming delay is the only guard against a click aimed
      // at something else.
      if (canTrackVisibility()) unguard = guard(view.card, approve);
      else approve.arm(ARM_MS);
    });
  }

  private async showConsent(action: ConsentAction): Promise<boolean> {
    const copy = CONSENT_COPY[action];
    const view = await this.open();
    view.title.textContent = copy.title;
    view.body.append(el("span", {}, copy.body));
    let typed: HTMLInputElement | undefined;
    if (action === "delete_account") {
      typed = el("input", {
        display: "block",
        width: "100%",
        boxSizing: "border-box",
        marginTop: "16px",
        padding: "11px 14px",
        borderRadius: "10px",
        border: "1px solid rgba(255,255,255,0.32)",
        background: "rgba(255,255,255,0.08)",
        color: "#FFFFFF",
        fontFamily: "inherit",
        fontSize: "15px",
        outline: "none",
      });
      typed.id = "cavos-consent-confirm";
      typed.type = "text";
      typed.autocomplete = "off";
      typed.placeholder = "Type delete to confirm";
      typed.setAttribute("aria-label", "Type delete to confirm");
      view.body.append(typed);
    }
    return new Promise((resolve) => {
      const cancel = button("Cancel", "secondary");
      let settled = false;
      let unguard = () => {};
      const finish = async (approved: boolean) => {
        if (settled) return;
        settled = true;
        unguard();
        document.removeEventListener("keydown", onKey);
        await this.dismiss(view);
        resolve(approved);
      };
      const onKey = (event: KeyboardEvent) => {
        if (event.key === "Escape") void finish(false);
      };
      document.addEventListener("keydown", onKey);
      cancel.onclick = () => void finish(false);

      const confirm = armableButton(copy.confirm);
      view.actions.append(confirm.node, cancel);
      confirm.node.onclick = () => void finish(true);

      let armed = false;
      let visible = !canTrackVisibility();
      const sync = () => {
        const ready = visible && (!typed || typed.value.trim().toLowerCase() === "delete");
        if (ready === armed) return;
        armed = ready;
        if (ready) confirm.arm(ARM_MS);
        else confirm.disarm();
      };
      if (typed) typed.oninput = sync;
      if (canTrackVisibility()) {
        unguard = guard(view.card, {
          node: confirm.node,
          arm: () => {
            visible = true;
            armed = false;
            sync();
          },
          disarm: () => {
            visible = false;
            armed = false;
            confirm.disarm();
          },
        });
      } else {
        sync();
      }
    });
  }

  /** `create` adds a passkey to a wallet; otherwise an existing passkey opens it on this device. */
  private async showPasskey(
    user: { userId: string; userName: string },
    mode: { create: boolean; credentialId?: Uint8Array },
  ): Promise<Secret> {
    const { create: creating, credentialId } = mode;
    const view = await this.open();
    return new Promise((resolve, reject) => {
      view.title.textContent = creating ? "Add a passkey" : "Verify it's you";
      const message = el(
        "span",
        {},
        creating
          ? "Your passkey will open this wallet on your other devices."
          : "Use your passkey to continue on this device.",
      );
      view.body.append(message);

      const passkeys = new PasskeyPrf({ rpName: "Cavos" });
      const use = button("Use passkey", "primary");
      const create = button("Create passkey", "primary");
      const cancel = button("Cancel", "quiet");
      view.actions.append(creating ? create : use, cancel);

      let settled = false;
      const finish = async (result: Secret | Error) => {
        if (settled) return;
        settled = true;
        await this.dismiss(view);
        if (result instanceof Error) reject(result);
        else resolve(result);
      };
      const attempt = async (run: () => Promise<Secret>) => {
        [use, create].forEach((b) => setEnabled(b, false));
        try {
          await finish(await run());
        } catch {
          // Some browsers refuse passkeys inside a cross-site frame; a Cavos window always works.
          message.textContent = "Your browser needs a Cavos window to use your passkey.";
          const fallback = button("Continue in a Cavos window", "primary");
          fallback.onclick = () =>
            this.popup({ kind: "passkey", ...user, create: creating, credentialId }).then(
              (result) => finish("secret" in result ? result : new Error("error" in result ? result.error : "kit/vault: cancelled")),
              (error: Error) => finish(error),
            );
          view.actions.replaceChildren(fallback, cancel);
          fallback.focus({ preventScroll: true });
        }
      };

      use.onclick = () => attempt(async () => ({ secret: await passkeys.getSecret(credentialId), credentialId }));
      create.onclick = () =>
        attempt(async () => {
          const enrolled = await passkeys.enroll(user);
          const secret = enrolled.secret ?? (await passkeys.getSecret(enrolled.credentialId));
          return { secret, credentialId: enrolled.credentialId };
        });
      cancel.onclick = () => void finish(new Error("kit/vault: cancelled"));
    });
  }

  private popup(intent: PopupIntent): Promise<PopupResult> {
    return new Promise((resolve, reject) => {
      const popup = window.open(this.confirmUrl, "cavos-vault", "popup,width=420,height=560");
      if (!popup) {
        reject(new Error("kit/vault: allow pop-ups for this site and try again"));
        return;
      }
      const timer = setInterval(() => {
        if (popup.closed) done({ error: "kit/vault: the Cavos window was closed" });
      }, 400);
      const onMessage = (event: MessageEvent) => {
        if (event.source !== popup || event.origin !== location.origin) return;
        if (event.data?.type === POPUP_READY) popup.postMessage(intent, location.origin);
        if (event.data?.type === POPUP_RESULT) done(event.data.result as PopupResult);
      };
      const done = (result: PopupResult) => {
        clearInterval(timer);
        window.removeEventListener("message", onMessage);
        resolve(result);
      };
      window.addEventListener("message", onMessage);
    });
  }
}

/** The frame is display:none until the app reveals it, and a hidden frame has no width to lay out against. */
function viewportReady(): Promise<void> {
  return new Promise((resolve) => {
    const check = () => (window.innerWidth > 0 ? resolve() : requestAnimationFrame(check));
    check();
  });
}

/**
 * Arms Approve only while the modal is actually on screen: covering or fading
 * the frame from the embedding page disarms it and the fill starts over.
 */
function guard(target: Element, approve: Armable): () => void {
  let visible = false;
  const observer = new IntersectionObserver(
    ([entry]) => {
      const now = (entry as IntersectionObserverEntry & { isVisible?: boolean }).isVisible === true;
      if (now === visible) return;
      visible = now;
      if (visible) approve.arm(ARM_MS);
      else approve.disarm();
    },
    { threshold: [0], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
  );
  observer.observe(target);
  return () => observer.disconnect();
}
