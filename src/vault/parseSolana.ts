import { SystemProgram, VersionedMessage, type MessageCompiledInstruction } from "@solana/web3.js";
import { emptyParsed, flag, formatUnits, short, type ParsedTx } from "./policy";

const SYSTEM_PROGRAM = SystemProgram.programId.toBase58();
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";
const MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const ASSOCIATED_TOKEN = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const TOKEN_PROGRAMS = new Set([
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
]);
const TOKEN_SYMBOLS: Record<string, string> = {
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: "USDC",
  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU": "USDC",
};
const SYSTEM_TRANSFER = 2;
const TOKEN_TRANSFER_CHECKED = 12;
const SET_COMPUTE_UNIT_LIMIT = 2;
const SET_COMPUTE_UNIT_PRICE = 3;
const LAMPORTS_PER_SIGNATURE = 5_000n;
const DEFAULT_UNITS_PER_INSTRUCTION = 200_000n;
const MAX_UNITS = 1_400_000n;
/** Rent-exempt minimum of a 165-byte token account; Token-2022 extensions can cost more. */
const TOKEN_ACCOUNT_RENT = 2_039_280n;

/**
 * Only instructions that list the account can use its signature, and within
 * them only the roles below are understood. The account anywhere else, or any
 * program not listed here, is outside every limit.
 */
export function parseSolanaMessage(bytes: Uint8Array, account: string): ParsedTx {
  const tx = emptyParsed();
  let message: VersionedMessage;
  try {
    message = VersionedMessage.deserialize(bytes);
  } catch {
    flag(tx, "Unreadable transaction");
    return tx;
  }
  const keys = message.staticAccountKeys.map((key) => key.toBase58());
  const self = keys.indexOf(account);
  if (self < 0) {
    flag(tx, "Transaction does not involve this account");
    return tx;
  }

  for (const ix of message.compiledInstructions) {
    const program = keys[ix.programIdIndex];
    const roles = ix.accountKeyIndexes.flatMap((index, position) => (index === self ? [position] : []));
    if (program === COMPUTE_BUDGET || roles.length === 0 || program === MEMO) continue;
    const accounts = ix.accountKeyIndexes.map((index) => keys[index]);

    if (program === SYSTEM_PROGRAM && readU32(ix.data, 0) === SYSTEM_TRANSFER && ix.data.length >= 12) {
      if (same(roles, [1])) continue;
      if (!same(roles, [0])) {
        flag(tx, "Use this account in a system instruction");
        continue;
      }
      const lamports = readU64(ix.data, 4);
      tx.spends.push({ asset: "SOL", amount: lamports, decimals: 9 });
      tx.lines.push({ kind: "send", amount: formatUnits(lamports, 9), asset: "SOL", to: accounts[1] ?? "unknown" });
    } else if (program && TOKEN_PROGRAMS.has(program) && ix.data[0] === TOKEN_TRANSFER_CHECKED && ix.data.length >= 10) {
      const [, mint, destination] = accounts;
      if (!same(roles, [3]) || !mint) {
        flag(tx, "Use this account in a token instruction");
        continue;
      }
      const amount = readU64(ix.data, 1);
      tx.spends.push({ asset: mint, amount, decimals: ix.data[9] });
      tx.lines.push({
        kind: "send",
        amount: formatUnits(amount, ix.data[9]),
        asset: TOKEN_SYMBOLS[mint] ?? short(mint),
        to: destination ?? "unknown",
      });
    } else if (program === ASSOCIATED_TOKEN && isAtaCreate(ix) && roles.every((role) => role === 0 || role === 2)) {
      if (roles.includes(0)) {
        tx.spends.push({ asset: "SOL", amount: TOKEN_ACCOUNT_RENT, decimals: 9 });
        tx.lines.push({ kind: "action", text: `Open a token account (${formatUnits(TOKEN_ACCOUNT_RENT, 9)} SOL)` });
      }
    } else {
      flag(tx, "Call a program", program);
    }
  }

  if (self === 0) readFee(message, tx);
  return tx;
}

/** The fee payer is the first key. Its fee is a spend like any other. */
function readFee(message: VersionedMessage, tx: ParsedTx): void {
  let price = 0n;
  let limit: bigint | undefined;
  let counted = 0n;
  for (const ix of message.compiledInstructions) {
    if (message.staticAccountKeys[ix.programIdIndex]?.toBase58() !== COMPUTE_BUDGET) {
      counted += 1n;
      continue;
    }
    if (ix.data[0] === SET_COMPUTE_UNIT_LIMIT && ix.data.length >= 5) limit = BigInt(readU32(ix.data, 1) ?? 0);
    if (ix.data[0] === SET_COMPUTE_UNIT_PRICE && ix.data.length >= 9) price = readU64(ix.data, 1);
  }
  const defaultUnits = counted * DEFAULT_UNITS_PER_INSTRUCTION;
  const units = limit ?? (defaultUnits < MAX_UNITS ? defaultUnits : MAX_UNITS);
  const priority = (price * units + 999_999n) / 1_000_000n;
  const fee = LAMPORTS_PER_SIGNATURE * BigInt(message.header.numRequiredSignatures) + priority;
  tx.spends.push({ asset: "SOL", amount: fee, decimals: 9 });
  if (priority > 0n) tx.lines.push({ kind: "action", text: `Network fee ${formatUnits(fee, 9)} SOL` });
}

function isAtaCreate(ix: MessageCompiledInstruction): boolean {
  return ix.data.length === 0 || (ix.data.length === 1 && (ix.data[0] === 0 || ix.data[0] === 1));
}

function same(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function readU32(data: Uint8Array, offset: number): number | undefined {
  if (data.length < offset + 4) return undefined;
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, true);
}

function readU64(data: Uint8Array, offset: number): bigint {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, true);
}
