/**
 * Plain DOM, styled through CSSOM only: the vault pages run under a CSP with no
 * style sources, which blocks <style> tags and pseudo-classes but not
 * `element.style`, so hover, press and focus are wired with events.
 */

const INDIGO = "#402AFF";
const WHITE = "#FFFFFF";
const SOFT = "rgba(255, 255, 255, 0.74)";
const HAIRLINE = "rgba(255, 255, 255, 0.16)";
const WELL = "rgba(255, 255, 255, 0.08)";
const SCRIM = "rgba(12, 8, 38, 0.56)";
const MONO = '"Geist Mono", ui-monospace, "SF Mono", Menlo, monospace';
const FONT = '"Geist", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif';
const EASE_OUT = "cubic-bezier(0.23, 1, 0.32, 1)";
const EASE_DRAWER = "cubic-bezier(0.32, 0.72, 0, 1)";

type Style = Partial<CSSStyleDeclaration>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  style: Style = {},
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  Object.assign(node.style, style);
  if (text !== undefined) node.textContent = text;
  return node;
}

const media = (query: string) => typeof window !== "undefined" && window.matchMedia(query).matches;
const isMobile = () => media("(max-width: 640px)");
const reducedMotion = () => media("(prefers-reduced-motion: reduce)");
const canHover = () => media("(hover: hover) and (pointer: fine)");

export type ButtonKind = "primary" | "secondary" | "quiet";

const BUTTON: Record<ButtonKind, { rest: Style; hover: string }> = {
  primary: { rest: { background: WHITE, color: INDIGO, border: "1px solid transparent", fontWeight: "600" }, hover: "#EEEBFF" },
  secondary: { rest: { background: "transparent", color: WHITE, border: "1px solid rgba(255,255,255,0.32)", fontWeight: "500" }, hover: WELL },
  quiet: { rest: { background: "transparent", color: SOFT, border: "1px solid transparent", fontWeight: "500" }, hover: WELL },
};

export function button(label: string, kind: ButtonKind): HTMLButtonElement {
  const { rest, hover } = BUTTON[kind];
  const node = el("button", {
    position: "relative",
    overflow: "hidden",
    width: "100%",
    minHeight: "46px",
    padding: "11px 16px",
    borderRadius: "10px",
    fontFamily: "inherit",
    fontSize: "15px",
    letterSpacing: "-0.01em",
    cursor: "pointer",
    outline: "none",
    transition: `transform 120ms ${EASE_OUT}, background-color 150ms ease, opacity 150ms ease, box-shadow 150ms ease`,
    ...rest,
  }, label);
  node.type = "button";
  const resting = () => (node.dataset.rest ?? rest.background ?? "transparent") as string;
  node.addEventListener("pointerenter", () => {
    if (canHover() && !node.disabled) node.style.background = hover;
  });
  node.addEventListener("pointerleave", () => {
    node.style.background = resting();
    node.style.transform = "";
  });
  node.addEventListener("pointerdown", () => {
    if (!node.disabled) node.style.transform = "scale(0.97)";
  });
  node.addEventListener("pointerup", () => (node.style.transform = ""));
  node.addEventListener("focus", () => {
    if (node.matches(":focus-visible")) node.style.boxShadow = `0 0 0 2px ${INDIGO}, 0 0 0 4px ${WHITE}`;
  });
  node.addEventListener("blur", () => (node.style.boxShadow = ""));
  return node;
}

export function setEnabled(node: HTMLButtonElement, enabled: boolean): void {
  node.disabled = !enabled;
  node.style.opacity = enabled ? "1" : "0.5";
  node.style.cursor = enabled ? "pointer" : "default";
}

export interface Armable {
  node: HTMLButtonElement;
  /** Fill the button over `ms`, then enable it. */
  arm(ms: number): void;
  disarm(): void;
}

/**
 * A primary button that fills in before it can be pressed. The fill is a white
 * copy of the button revealed with clip-path, so the label turns indigo exactly
 * where the fill has reached.
 */
export function armableButton(label: string): Armable {
  const node = button("", "primary");
  const unarmed = "rgba(255,255,255,0.18)";
  node.dataset.rest = unarmed;
  Object.assign(node.style, { background: unarmed, color: WHITE });
  node.setAttribute("aria-label", label);

  const layer = (color: string, background: string) =>
    el("span", {
      position: "absolute",
      inset: "0",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      color,
      background,
      pointerEvents: "none",
    }, label);
  const base = layer(WHITE, "transparent");
  const fill = layer(INDIGO, WHITE);
  fill.setAttribute("aria-hidden", "true");
  base.setAttribute("aria-hidden", "true");
  node.append(base, fill);

  let sweep: Animation | undefined;
  const disarm = () => {
    sweep?.cancel();
    fill.style.clipPath = "inset(0 100% 0 0)";
    node.dataset.rest = unarmed;
    node.style.background = unarmed;
    node.disabled = true;
    node.style.cursor = "default";
  };
  disarm();
  return {
    node,
    disarm,
    arm(ms) {
      disarm();
      sweep = fill.animate([{ clipPath: "inset(0 100% 0 0)" }, { clipPath: "inset(0 0% 0 0)" }], {
        duration: reducedMotion() ? 1 : ms,
        easing: "linear",
      });
      sweep.onfinish = () => {
        fill.style.clipPath = "inset(0 0 0 0)";
        node.dataset.rest = WHITE;
        node.style.background = WHITE;
        node.disabled = false;
        node.style.cursor = "pointer";
      };
    },
  };
}

export function mark(size = 20): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String((size * 82) / 66));
  svg.setAttribute("viewBox", "0 0 66 82");
  svg.setAttribute("fill", WHITE);
  svg.setAttribute("aria-hidden", "true");
  const g = document.createElementNS(ns, "g");
  g.setAttribute("transform", "translate(0,82) scale(0.1,-0.1)");
  const path = document.createElementNS(ns, "path");
  path.setAttribute(
    "d",
    "M148 630 l-148 -185 68 -3 c193 -9 236 39 230 264 l-3 108 -147 -184z M360 705 c1 -225 37 -269 217 -263 l83 3 -136 170 c-74 94 -142 177 -150 185 -12 12 -14 0 -14 -95z M125 223 c69 -87 136 -171 150 -188 l26 -30 -4 135 c-6 212 -29 240 -201 240 l-96 0 125 -157z M433 364 c-53 -26 -67 -70 -71 -224 -3 -118 -2 -133 11 -120 8 8 76 93 151 188 l136 172 -97 0 c-68 0 -108 -5 -130 -16z",
  );
  g.append(path);
  svg.append(g);
  return svg;
}

export interface Sheet {
  root: HTMLDivElement;
  card: HTMLDivElement;
  title: HTMLHeadingElement;
  body: HTMLDivElement;
  actions: HTMLDivElement;
  close(): Promise<void>;
}

let sheets = 0;

/**
 * The Cavos card: an indigo panel over a scrim, centred on desktop and a
 * bottom sheet on phones. `overlay: false` fills the page (the pop-up window).
 */
export function sheet(options: { overlay: boolean }): Sheet {
  const mobile = options.overlay && isMobile();
  const id = `cavos-sheet-${++sheets}`;
  const root = el("div", {
    position: "fixed",
    inset: "0",
    display: "flex",
    alignItems: mobile ? "flex-end" : "center",
    justifyContent: "center",
    padding: options.overlay && !mobile ? "16px" : "0",
    fontFamily: FONT,
    color: WHITE,
    background: options.overlay ? SCRIM : INDIGO,
  });
  root.style.setProperty("-webkit-font-smoothing", "antialiased");

  const card = el("div", {
    width: "100%",
    maxWidth: options.overlay && !mobile ? "392px" : "100%",
    maxHeight: "100%",
    overflowY: "auto",
    boxSizing: "border-box",
    padding: mobile ? "24px 20px calc(20px + env(safe-area-inset-bottom))" : "28px",
    borderRadius: mobile ? "20px 20px 0 0" : options.overlay ? "18px" : "0",
    // A faint light from the top right, as on the Cavos demo; flat indigo reads as a sticker.
    background: `radial-gradient(420px 220px at 88% -12%, rgba(255,255,255,0.16), transparent 62%), ${INDIGO}`,
    boxShadow: options.overlay
      ? "inset 0 1px 0 rgba(255,255,255,0.18), 0 32px 80px rgba(16, 8, 72, 0.5), 0 0 0 1px rgba(255,255,255,0.06)"
      : "none",
    ...(options.overlay ? {} : { minHeight: "100%", display: "flex", flexDirection: "column", justifyContent: "center" }),
  });
  card.tabIndex = -1;
  card.style.outline = "none";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  card.setAttribute("aria-labelledby", `${id}-title`);
  card.setAttribute("aria-describedby", `${id}-body`);

  const inner = el("div", { width: "100%", maxWidth: "392px", margin: "0 auto" });
  const header = el("div", { display: "flex", alignItems: "center", gap: "8px", marginBottom: "28px" });
  header.append(mark(18));

  const title = el("h1", {
    margin: "0 0 8px",
    fontSize: "22px",
    lineHeight: "1.2",
    fontWeight: "600",
    letterSpacing: "-0.022em",
    color: WHITE,
  });
  title.style.setProperty("text-wrap", "balance");
  title.id = `${id}-title`;
  const body = el("div", { fontSize: "15px", lineHeight: "1.5", color: SOFT, letterSpacing: "-0.006em" });
  body.id = `${id}-body`;
  const actions = el("div", { display: "flex", flexDirection: "column", gap: "8px", marginTop: "28px" });
  inner.append(header, title, body, actions);
  card.append(inner);
  root.append(card);
  document.body.append(root);
  // Focus the dialog, not a button, so Enter never approves by accident.
  card.focus({ preventScroll: true });

  const still = reducedMotion();
  const enter: Keyframe[] = still
    ? [{ opacity: 0 }, { opacity: 1 }]
    : mobile
      ? [{ transform: "translateY(100%)" }, { transform: "translateY(0)" }]
      : [{ opacity: 0, transform: "translateY(10px) scale(0.97)" }, { opacity: 1, transform: "none" }];
  if (options.overlay) root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, easing: "ease-out" });
  card.animate(enter, { duration: still ? 150 : mobile ? 420 : 260, easing: mobile ? EASE_DRAWER : EASE_OUT });

  return {
    root,
    card,
    title,
    body,
    actions,
    async close() {
      // Leave the way it came, faster than it arrived.
      const duration = still ? 120 : mobile ? 240 : 160;
      card.animate([...enter].reverse(), { duration, easing: "cubic-bezier(0.4, 0, 1, 1)", fill: "forwards" });
      await root.animate([{ opacity: 1 }, { opacity: 0 }], { duration: duration + 10, easing: "ease-in", fill: "forwards" }).finished;
      root.remove();
    },
  };
}

/** The amount, large, as the thing being approved. */
export function amountHero(amount: string, asset: string): HTMLDivElement {
  const wrap = el("div", { margin: "0 0 24px" });
  const figure = el("div", {
    display: "flex",
    alignItems: "baseline",
    gap: "8px",
    flexWrap: "wrap",
    fontSize: "44px",
    lineHeight: "1.05",
    fontWeight: "600",
    letterSpacing: "-0.035em",
    fontVariantNumeric: "tabular-nums",
  });
  figure.append(el("span", { color: WHITE }, amount), el("span", { color: SOFT, fontSize: "28px", letterSpacing: "-0.02em" }, asset));
  wrap.append(figure);
  return wrap;
}

export interface Detail {
  label: string;
  value: string;
  /** Shown on hover and selectable in full, when `value` is shortened. */
  full?: string;
  mono?: boolean;
}

/** Label and value pairs separated by hairlines, no box. */
export function details(rows: Detail[]): HTMLDListElement {
  const list = el("dl", { margin: "0" });
  for (const row of rows) {
    const line = el("div", {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "baseline",
      gap: "16px",
      padding: "12px 0",
      borderTop: `1px solid ${HAIRLINE}`,
    });
    const value = el("dd", {
      margin: "0",
      fontSize: row.mono ? "13px" : "14px",
      fontFamily: row.mono ? MONO : "inherit",
      fontWeight: "500",
      color: WHITE,
      textAlign: "right",
      minWidth: "0",
      overflowWrap: "anywhere",
      userSelect: "all",
    }, row.value);
    if (row.full) value.title = row.full;
    line.append(el("dt", { fontSize: "14px", color: SOFT, flexShrink: "0" }, row.label), value);
    list.append(line);
  }
  return list;
}

export function shortAddress(address: string): string {
  return address.length > 16 ? `${address.slice(0, 6)}…${address.slice(-6)}` : address;
}

/** For screens whose headline is the amount: the h1 stays for screen readers but reads as a label. */
export function quietTitle(title: HTMLElement): void {
  Object.assign(title.style, { fontSize: "14px", fontWeight: "500", letterSpacing: "0", color: SOFT, margin: "0 0 6px" });
}

export function caption(text: string): HTMLParagraphElement {
  const node = el("p", { margin: "16px 0 0", fontSize: "13px", lineHeight: "1.45", color: SOFT }, text);
  node.style.setProperty("text-wrap", "pretty");
  return node;
}
