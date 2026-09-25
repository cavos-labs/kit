import { Buffer } from "buffer";
import { PublicKey, TransactionInstruction } from "@solana/web3.js";

export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey(
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
);

/** The canonical token account for `owner` and `mint`. */
export function associatedTokenAddress(mint: PublicKey, owner: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBytes(), TOKEN_PROGRAM_ID.toBytes(), mint.toBytes()],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  )[0];
}

const TRANSFER_CHECKED = 12;

/**
 * `TransferChecked`, not the bare `Transfer`: it names the mint and decimals in
 * the instruction, so the receiver can tell a real token from a look-alike
 * without reading the source account. Toll requires it for exactly that reason.
 *
 * Accounts are `[source, mint, destination, authority]`.
 */
export function transferCheckedInstruction(params: {
  source: PublicKey;
  mint: PublicKey;
  destination: PublicKey;
  authority: PublicKey;
  amount: bigint;
  decimals: number;
}): TransactionInstruction {
  // Written byte by byte rather than with `writeBigUInt64LE`: the global
  // `Buffer` a bundler hands the browser is often a thin shim without the
  // BigInt methods, and this needs no more than shifts.
  const data = Buffer.alloc(10);
  data[0] = TRANSFER_CHECKED;
  let amount = params.amount;
  for (let i = 0; i < 8; i++) {
    data[1 + i] = Number(amount & 0xffn);
    amount >>= 8n;
  }
  data[9] = params.decimals;
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: params.source, isSigner: false, isWritable: true },
      { pubkey: params.mint, isSigner: false, isWritable: false },
      { pubkey: params.destination, isSigner: false, isWritable: true },
      { pubkey: params.authority, isSigner: true, isWritable: false },
    ],
    data,
  });
}
