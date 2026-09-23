import type { VaultLimit, VaultPolicy } from "./limits";

export interface Spend {
  asset: string;
  /** Base units: lamports, stroops, or the token's smallest unit. */
  amount: bigint;
  decimals: number;
}

/** What the user reads when the vault asks: sends get their own layout, everything else a line of text. */
export type Line =
  | { kind: "send"; amount: string; asset: string; to: string }
  | { kind: "action"; text: string; target?: string };

export interface ParsedTx {
  spends: Spend[];
  lines: Line[];
  /** Signer changes, unknown programs: never inside a limit, so the app's over-limit rule decides. */
  flagged: boolean;
}

export type Decision = "sign" | "confirm" | "block";

export function emptyParsed(): ParsedTx {
  return { spends: [], lines: [], flagged: false };
}

export function flag(tx: ParsedTx, text: string, target?: string): void {
  tx.flagged = true;
  tx.lines.push({ kind: "action", text, ...(target ? { target } : {}) });
}

export function totals(spends: Spend[]): Map<string, { amount: bigint; decimals: number }> {
  const out = new Map<string, { amount: bigint; decimals: number }>();
  for (const { asset, amount, decimals } of spends) {
    out.set(asset, { amount: (out.get(asset)?.amount ?? 0n) + amount, decimals });
  }
  return out;
}

export function evaluate(tx: ParsedTx, spentToday: ReadonlyMap<string, bigint>, policy: VaultPolicy): Decision {
  if (!tx.flagged && withinLimits(tx, spentToday, policy.limits)) return "sign";
  return policy.overLimit === "ask" ? "confirm" : policy.overLimit;
}

function withinLimits(tx: ParsedTx, spentToday: ReadonlyMap<string, bigint>, limits: VaultLimit[]): boolean {
  for (const [asset, { amount, decimals }] of totals(tx.spends)) {
    const limit = limits.find((entry) => entry.asset === asset);
    if (!limit) return false;
    if (amount > parseUnits(limit.perTx, decimals)) return false;
    if ((spentToday.get(asset) ?? 0n) + amount > parseUnits(limit.perDay, decimals)) return false;
  }
  return true;
}

/** "0.5" at 9 decimals is 500000000n. Extra digits are dropped, which only ever lowers a limit. */
export function parseUnits(amount: string, decimals: number): bigint {
  const [whole, fraction = ""] = amount.trim().split(".");
  return BigInt(whole || "0") * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, "0").slice(0, decimals) || "0");
}

export function formatUnits(amount: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals);
  const whole = amount / base;
  const fraction = (amount % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

export function short(address: string): string {
  return address.length > 12 ? `${address.slice(0, 4)}…${address.slice(-4)}` : address;
}
