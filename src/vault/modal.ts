import { PasskeyPrf } from "../chains/stellar/PasskeyPrf";
import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { POPUP_READY, POPUP_RESULT, type PopupIntent, type PopupResult } from "./protocol";
import type { Line } from "./policy";
import { canTrackVisibility, hostOf, renderReview } from "./review";
import { armableButton, button, el, setEnabled, sheet, type Armable, type Sheet } from "./ui";

/** Approve fills in over this long once the modal is seen, so a click aimed at something else cannot land on it. */
const ARM_MS = 700;

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

  passkey(user: { userId: string; userName: string }): PasskeyPrfProvider {
    return {
      enroll: async () => {
        const { secret, credentialId } = await this.serial(() => this.showPasskey(user));
        return { credentialId: credentialId ?? new Uint8Array(), secret };
      },
      getSecret: async (credentialId) => (await this.serial(() => this.showPasskey(user, credentialId))).secret,
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

      if (canTrackVisibility()) {
        const approve = armableButton("Approve");
        view.actions.append(approve.node, reject);
        unguard = guard(view.card, approve);
        approve.node.onclick = () => void finish(true);
        return;
      }
      // Without a way to tell whether the page is covering this frame, the
      // decision is taken in a top-level Cavos window the page cannot draw over.
      const review = button("Review in a Cavos window", "primary");
      view.actions.append(review, reject);
      review.onclick = () =>
        this.popup({ kind: "review", lines, network, app: hostOf(this.origin) }).then(
          (result) => finish("approved" in result && result.approved),
          () => finish(false),
        );
    });
  }

  private async showPasskey(user: { userId: string; userName: string }, credentialId?: Uint8Array): Promise<Secret> {
    const view = await this.open();
    return new Promise((resolve, reject) => {
      view.title.textContent = "Unlock your wallet";
      const message = el("span", {}, "Use your passkey to open your wallet on this site.");
      view.body.append(message);

      const passkeys = new PasskeyPrf({ rpName: "Cavos" });
      const use = button("Use passkey", "primary");
      const create = button("Create a passkey", "secondary");
      const cancel = button("Cancel", "quiet");
      view.actions.append(use, create, cancel);

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
            this.popup({ kind: "passkey", ...user, credentialId }).then(
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
