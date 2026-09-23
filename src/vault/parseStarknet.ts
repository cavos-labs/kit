import { hash, type TypedData } from "starknet";
import { emptyParsed, flag, formatUnits, type ParsedTx } from "./policy";

export interface StarknetCall {
  to: string;
  selector: string;
  calldata: string[];
}

/** Mainnet and Sepolia share the ETH and STRK addresses. */
const TOKENS = new Map<bigint, { symbol: string; decimals: number }>([
  [BigInt("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"), { symbol: "ETH", decimals: 18 }],
  [BigInt("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"), { symbol: "STRK", decimals: 18 }],
  [BigInt("0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb"), { symbol: "USDC", decimals: 6 }],
  [BigInt("0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8"), { symbol: "USDC", decimals: 6 }],
]);

const TRANSFER = BigInt(hash.getSelectorFromName("transfer"));
const APPROVALS = new Set(["approve", "increase_allowance", "increaseAllowance"].map((name) => BigInt(hash.getSelectorFromName(name))));

export function selectorOf(entrypoint: string): string {
  return /^0x[0-9a-f]+$/i.test(entrypoint) ? entrypoint : hash.getSelectorFromName(entrypoint);
}

/**
 * Only transfers of known tokens become spends. Calls into the account itself
 * change who controls it, so they, like everything else, are never within a limit.
 */
export function parseStarknetCalls(calls: StarknetCall[], account: string): ParsedTx {
  const tx = emptyParsed();
  const self = BigInt(account);
  for (const call of calls) {
    const to = BigInt(call.to);
    const selector = BigInt(call.selector);
    const token = TOKENS.get(to);
    if (to === self) {
      flag(tx, "Change this account's signers or settings");
    } else if (token && selector === TRANSFER && call.calldata.length >= 3) {
      const [recipient, low, high] = call.calldata;
      const amount = BigInt(low) + (BigInt(high) << 128n);
      tx.spends.push({ asset: token.symbol, amount, decimals: token.decimals });
      tx.lines.push({ kind: "send", amount: formatUnits(amount, token.decimals), asset: token.symbol, to: hex(recipient) });
    } else if (APPROVALS.has(selector)) {
      flag(tx, `Let another address spend your ${token?.symbol ?? "tokens"}`, call.calldata[0] ? hex(call.calldata[0]) : undefined);
    } else {
      flag(tx, "Call a contract", hex(call.to));
    }
  }
  return tx;
}

/** Sponsored transactions are signed as a SNIP-9 OutsideExecution, which carries the calls. */
export function parseStarknetTypedData(typedData: TypedData, account: string): ParsedTx {
  const message = typedData.message as Record<string, unknown>;
  const calls = (message.Calls ?? message.calls) as Record<string, unknown>[] | undefined;
  if (typedData.primaryType !== "OutsideExecution" || !Array.isArray(calls)) {
    const tx = emptyParsed();
    flag(tx, "Sign a typed message");
    return tx;
  }
  return parseStarknetCalls(
    calls.map((call) => ({
      to: String(call.To ?? call.to),
      selector: String(call.Selector ?? call.selector),
      calldata: ((call.Calldata ?? call.calldata) as unknown[]).map(String),
    })),
    account,
  );
}

/** Fee estimates are signed with a query version, which the network refuses to execute. */
export function isQueryVersion(version: unknown): boolean {
  try {
    return BigInt(version as string | number | bigint) >= 1n << 128n;
  } catch {
    return false;
  }
}

function hex(value: string): string {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}
