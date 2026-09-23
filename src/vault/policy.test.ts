import {
  ComputeBudgetProgram,
  Keypair as SolanaKeypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  Account,
  Address,
  Asset,
  Keypair,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
  hash,
  xdr,
} from "@stellar/stellar-sdk";
import type { VaultPolicy } from "./limits";
import { evaluate, type ParsedTx } from "./policy";
import { parseSolanaMessage } from "./parseSolana";
import { parseStellarAuthEntry, parseStellarTransaction } from "./parseStellar";

const BLOCKHASH = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const TOKEN_PROGRAM = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

const none = new Map<string, bigint>();

function solanaMessage(payer: PublicKey, ...ixs: TransactionInstruction[]): Uint8Array {
  const tx = new Transaction();
  tx.feePayer = payer;
  tx.recentBlockhash = BLOCKHASH;
  tx.add(...ixs);
  return tx.serializeMessage();
}

function transferChecked(owner: PublicKey, mint: string, amount: bigint): TransactionInstruction {
  const data = Buffer.alloc(10);
  data[0] = 12;
  data.writeBigUInt64LE(amount, 1);
  data[9] = 6;
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM,
    keys: [
      { pubkey: SolanaKeypair.generate().publicKey, isSigner: false, isWritable: true },
      { pubkey: new PublicKey(mint), isSigner: false, isWritable: false },
      { pubkey: SolanaKeypair.generate().publicKey, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function stellarTx(source: string, ...ops: xdr.Operation[]): string {
  const builder = new TransactionBuilder(new Account(source, "1"), { fee: "100", networkPassphrase: Networks.TESTNET });
  for (const op of ops) builder.addOperation(op);
  return builder.setTimeout(30).build().toXDR();
}

describe("evaluate", () => {
  const policy: VaultPolicy = {
    overLimit: "ask",
    limits: [{ chain: "solana", asset: "SOL", perTx: "0.1", perDay: "0.5" }],
  };
  const sol = (lamports: bigint) => ({ asset: "SOL", amount: lamports, decimals: 9 });
  const parsed = (spends: ParsedTx["spends"], flagged = false): ParsedTx => ({ spends, lines: [], flagged });

  it("signs a spend inside the per-transaction and daily limits", () => {
    expect(evaluate(parsed([sol(50_000_000n)]), none, policy)).toBe("sign");
  });

  it("asks above the per-transaction limit", () => {
    expect(evaluate(parsed([sol(100_000_001n)]), none, policy)).toBe("confirm");
  });

  it("adds up spends of the same asset within one transaction", () => {
    expect(evaluate(parsed([sol(60_000_000n), sol(60_000_000n)]), none, policy)).toBe("confirm");
  });

  it("asks once the day's total would pass the daily limit", () => {
    expect(evaluate(parsed([sol(60_000_000n)]), new Map([["SOL", 450_000_000n]]), policy)).toBe("confirm");
  });

  it("asks for an asset the app did not list", () => {
    expect(evaluate(parsed([{ asset: "SCAM", amount: 1n, decimals: 6 }]), none, policy)).toBe("confirm");
  });

  it("asks whenever the parser flagged the transaction", () => {
    expect(evaluate(parsed([], true), none, policy)).toBe("confirm");
  });

  it("follows the app's rule for anything over the limit", () => {
    const over = parsed([sol(1_000_000_000n)]);
    expect(evaluate(over, none, { ...policy, overLimit: "block" })).toBe("block");
    expect(evaluate(over, none, { ...policy, overLimit: "sign" })).toBe("sign");
  });

  it("reads limits in the token's own decimals", () => {
    const usdc: VaultPolicy = { overLimit: "ask", limits: [{ chain: "solana", asset: "MINT", perTx: "25", perDay: "100" }] };
    expect(evaluate(parsed([{ asset: "MINT", amount: 25_000_000n, decimals: 6 }]), none, usdc)).toBe("sign");
    expect(evaluate(parsed([{ asset: "MINT", amount: 25_000_001n, decimals: 6 }]), none, usdc)).toBe("confirm");
  });
});

describe("parseSolanaMessage", () => {
  const owner = SolanaKeypair.generate().publicKey;
  const account = owner.toBase58();

  it("reads a SOL transfer from the account", () => {
    const to = SolanaKeypair.generate().publicKey;
    const parsed = parseSolanaMessage(
      solanaMessage(owner, SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1_500_000_000 })),
      account,
    );
    expect(parsed.spends).toEqual([
      { asset: "SOL", amount: 1_500_000_000n, decimals: 9 },
      { asset: "SOL", amount: 5_000n, decimals: 9 },
    ]);
    expect(parsed.flagged).toBe(false);
    expect(parsed.lines).toEqual([{ kind: "send", amount: "1.5", asset: "SOL", to: to.toBase58() }]);
  });

  it("reads a token transferChecked signed by the account", () => {
    const parsed = parseSolanaMessage(solanaMessage(owner, transferChecked(owner, USDC_DEVNET, 2_000_000n)), account);
    expect(parsed.spends).toContainEqual({ asset: USDC_DEVNET, amount: 2_000_000n, decimals: 6 });
    expect(parsed.lines[0]).toMatchObject({ kind: "send", amount: "2", asset: "USDC" });
    expect(parsed.flagged).toBe(false);
  });

  it("ignores a transfer into the account", () => {
    const from = SolanaKeypair.generate().publicKey;
    const parsed = parseSolanaMessage(
      solanaMessage(from, SystemProgram.transfer({ fromPubkey: from, toPubkey: owner, lamports: 1 })),
      account,
    );
    expect(parsed.spends).toEqual([]);
    expect(parsed.flagged).toBe(false);
  });

  it("flags an unknown program that touches the account", () => {
    const ix = new TransactionInstruction({
      programId: SolanaKeypair.generate().publicKey,
      keys: [{ pubkey: owner, isSigner: true, isWritable: true }],
      data: Buffer.from([1]),
    });
    expect(parseSolanaMessage(solanaMessage(owner, ix), account).flagged).toBe(true);
  });

  it("flags a system instruction other than a transfer, such as assign", () => {
    const ix = SystemProgram.assign({ accountPubkey: owner, programId: SolanaKeypair.generate().publicKey });
    expect(parseSolanaMessage(solanaMessage(owner, ix), account).flagged).toBe(true);
  });

  it("counts the fee, priority fee included, when the account pays it", () => {
    const price = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000_000 });
    const limit = ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 });
    const to = SolanaKeypair.generate().publicKey;
    const parsed = parseSolanaMessage(
      solanaMessage(owner, limit, price, SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1 })),
      account,
    );
    expect(parsed.spends).toContainEqual({ asset: "SOL", amount: 200_005_000n, decimals: 9 });
  });

  it("flags the account in a role the parser does not know", () => {
    const hooked = transferChecked(SolanaKeypair.generate().publicKey, USDC_DEVNET, 1n);
    hooked.keys.push({ pubkey: owner, isSigner: true, isWritable: true });
    const payer = SolanaKeypair.generate().publicKey;
    expect(parseSolanaMessage(solanaMessage(payer, hooked), account).flagged).toBe(true);
  });

  it("counts the rent of a token account the account pays for", () => {
    const ix = new TransactionInstruction({
      programId: new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
      keys: [
        { pubkey: owner, isSigner: true, isWritable: true },
        { pubkey: SolanaKeypair.generate().publicKey, isSigner: false, isWritable: true },
        { pubkey: owner, isSigner: false, isWritable: false },
        { pubkey: new PublicKey(USDC_DEVNET), isSigner: false, isWritable: false },
      ],
      data: Buffer.from([1]),
    });
    const parsed = parseSolanaMessage(solanaMessage(owner, ix), account);
    expect(parsed.flagged).toBe(false);
    expect(parsed.spends).toContainEqual({ asset: "SOL", amount: 2_039_280n, decimals: 9 });
  });

  it("flags bytes that are not a message", () => {
    expect(parseSolanaMessage(new Uint8Array([1, 2, 3]), account).flagged).toBe(true);
  });
});

describe("parseStellarTransaction", () => {
  const account = Keypair.random().publicKey();
  const other = Keypair.random().publicKey();

  it("reads an XLM payment from the account", () => {
    const envelope = stellarTx(account, Operation.payment({ destination: other, asset: Asset.native(), amount: "12.5" }));
    const parsed = parseStellarTransaction(envelope, Networks.TESTNET, account);
    expect(parsed.spends).toEqual([{ asset: "XLM", amount: 125_000_000n, decimals: 7 }]);
    expect(parsed.lines).toEqual([{ kind: "send", amount: "12.5", asset: "XLM", to: other }]);
    expect(parsed.flagged).toBe(false);
  });

  it("names issued assets by code and issuer", () => {
    const usdc = new Asset("USDC", other);
    const envelope = stellarTx(account, Operation.payment({ destination: other, asset: usdc, amount: "1" }));
    expect(parseStellarTransaction(envelope, Networks.TESTNET, account).spends).toEqual([
      { asset: `USDC:${other}`, amount: 10_000_000n, decimals: 7 },
    ]);
  });

  it("always asks before changing signers", () => {
    const envelope = stellarTx(account, Operation.setOptions({ signer: { ed25519PublicKey: other, weight: 1 } }));
    expect(parseStellarTransaction(envelope, Networks.TESTNET, account).flagged).toBe(true);
  });

  it("always asks before merging the account away", () => {
    const envelope = stellarTx(account, Operation.accountMerge({ destination: other }));
    expect(parseStellarTransaction(envelope, Networks.TESTNET, account).flagged).toBe(true);
  });

  it("lets account setup through", () => {
    const envelope = stellarTx(
      account,
      Operation.changeTrust({ asset: new Asset("USDC", other) }),
      Operation.manageData({ name: "cv:m", value: "1" }),
    );
    const parsed = parseStellarTransaction(envelope, Networks.TESTNET, account);
    expect(parsed.flagged).toBe(false);
    expect(parsed.spends).toEqual([]);
  });

  it("skips operations sourced from another account, like a sponsor's", () => {
    const envelope = stellarTx(
      other,
      Operation.beginSponsoringFutureReserves({ sponsoredId: account }),
      Operation.createAccount({ destination: account, startingBalance: "0" }),
      Operation.endSponsoringFutureReserves({ source: account }),
    );
    const parsed = parseStellarTransaction(envelope, Networks.TESTNET, account);
    expect(parsed.flagged).toBe(false);
    expect(parsed.spends).toEqual([]);
  });

  it("reads the inner transaction of a fee bump", () => {
    const inner = TransactionBuilder.fromXDR(
      stellarTx(account, Operation.payment({ destination: other, asset: Asset.native(), amount: "1" })),
      Networks.TESTNET,
    );
    const bump = TransactionBuilder.buildFeeBumpTransaction(other, "200", inner as never, Networks.TESTNET);
    expect(parseStellarTransaction(bump.toXDR(), Networks.TESTNET, account).spends).toEqual([
      { asset: "XLM", amount: 10_000_000n, decimals: 7 },
    ]);
  });
});

describe("parseStellarAuthEntry", () => {
  const contract = StrKey.encodeContract(Buffer.alloc(32, 7));

  function preimage(): Uint8Array {
    const invocation = new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(contract).toScAddress(),
          functionName: "release_funds",
          args: [],
        }),
      ),
      subInvocations: [],
    });
    return new Uint8Array(
      xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
        new xdr.HashIdPreimageSorobanAuthorization({
          networkId: hash(Buffer.from(Networks.TESTNET)),
          nonce: xdr.Int64.fromString("1"),
          signatureExpirationLedger: 100,
          invocation,
        }),
      ).toXDR(),
    );
  }

  it("names the contract and method it would authorise", () => {
    const parsed = parseStellarAuthEntry(preimage());
    expect(parsed.flagged).toBe(true);
    expect(parsed.lines[0]).toEqual({ kind: "action", text: "Call release_funds", target: contract });
  });
});
