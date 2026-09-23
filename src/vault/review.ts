import type { Line } from "./policy";
import { amountHero, caption, details, el, quietTitle, shortAddress, type Detail, type Sheet } from "./ui";

/** What the user is asked to approve, the same in the vault frame and in the Cavos window. */
export function renderReview(view: Sheet, lines: Line[], network: string, app: string): void {
  const context: Detail[] = [
    { label: "App", value: app },
    { label: "Network", value: network },
  ];
  const [first] = lines;
  if (lines.length === 1 && first.kind === "send") {
    view.title.textContent = "Send";
    quietTitle(view.title);
    view.body.append(
      amountHero(first.amount, first.asset),
      details([{ label: "To", value: shortAddress(first.to), full: first.to, mono: true }, ...context]),
    );
  } else {
    view.title.textContent = "Approve this transaction";
    view.body.append(el("div", { height: "16px" }), details([...lines.map(lineDetail), ...context]));
  }
  view.body.append(caption("Cavos signs small amounts on its own. This one needs you."));
}

function lineDetail(line: Line): Detail {
  if (line.kind === "send") {
    return { label: `Send ${line.amount} ${line.asset}`, value: shortAddress(line.to), full: line.to, mono: true };
  }
  return line.target
    ? { label: line.text, value: shortAddress(line.target), full: line.target, mono: true }
    : { label: line.text, value: "" };
}

export function hostOf(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

/** Intersection Observer v2 can tell whether the page covers or fades the frame. */
export function canTrackVisibility(): boolean {
  return typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;
}
