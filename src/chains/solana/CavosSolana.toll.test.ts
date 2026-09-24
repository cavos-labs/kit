import { Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { CavosSolana } from "./CavosSolana";
import type { TollClient } from "./TollClient";
import { associatedTokenAddress, TOKEN_PROGRAM_ID } from "./spl";

/**
 * Paying the fee in a token: the payment and the user's own instruction are one
 * transaction, signed once.
 */
const SELF = new PublicKey("11111111111111111111111111111112");
const BLOCKHASH = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const MINT = Keypair.generate().publicKey;
const TREASURY = Keypair.generate().publicKey;
const TOLL_PAYER = Keypair.generate().publicKey;

function build(init: Record<string, unknown>): CavosSolana {
  const Ctor = CavosSolana as unknown as new (i: Record<string, unknown>) => CavosSolana;
  return new Ctor({ identity: { userId: "u1" }, address: SELF.toBase58(), status: "ready", ...init });
}

function makeToll(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    quote: jest.fn().mockResolvedValue({
      quote: "sealed",
      feePayer: TOLL_PAYER,
      treasury: TREASURY,
      mint: MINT,
      amount: 1_200n,
      decimals: 6,
      expiresAt: 2 ** 31,
    }),
    submit: jest.fn().mockResolvedValue("tollSig"),
    ...overrides,
  } as unknown as TollClient;
}

function makeWallet(toll?: TollClient, relayer?: unknown) {
  return build({
    connection: {
      getLatestBlockhash: async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 1 }),
      sendRawTransaction: jest.fn().mockResolvedValue("selfSig"),
      confirmTransaction: jest.fn().mockResolvedValue({ value: { err: null } }),
    },
    spend: {
      address: () => SELF.toBase58(),
      publicKeyRaw: () => SELF.toBytes(),
      signTransaction: async () => new Uint8Array(64),
    signMessage: async () => new Uint8Array(64),
    },
    toll,
    relayer,
  });
}

describe("CavosSolana — fee: { token }", () => {
  it("settles the quote and the transfer in one signed transaction", async () => {
    const toll = makeToll();
    const wallet = makeWallet(toll);
    const dest = Keypair.generate().publicKey;

    const sig = await wallet.execute(1_000n, dest.toBase58(), { fee: { token: MINT.toBase58() } });

    expect(sig).toBe("tollSig");
    const [sealed, serialized] = (toll.submit as jest.Mock).mock.calls[0]!;
    expect(sealed).toBe("sealed");

    // The payment rides in front of the user's own instruction.
    const decoded = Transaction.from(Buffer.from(serialized));
    expect(decoded.feePayer!.toBase58()).toBe(TOLL_PAYER.toBase58());
    expect(decoded.instructions).toHaveLength(2);
  });

  it("quotes for the instruction count the transaction will carry", async () => {
    const toll = makeToll();
    await makeWallet(toll).executeInstructions(
      [
        { programId: TOKEN_PROGRAM_ID.toBase58(), accounts: [], data: new Uint8Array([1]) },
        { programId: TOKEN_PROGRAM_ID.toBase58(), accounts: [], data: new Uint8Array([2]) },
      ],
      { fee: { token: MINT.toBase58() } },
    );
    // Two of the caller's, plus the payment.
    expect((toll.quote as jest.Mock).mock.calls[0]![0].instructions).toBe(3);
  });

  it("pays from the account's own token account, to the quoted treasury", async () => {
    const toll = makeToll();
    await makeWallet(toll).execute(1n, Keypair.generate().publicKey.toBase58(), {
      fee: { token: MINT.toBase58() },
    });

    const [, serialized] = (toll.submit as jest.Mock).mock.calls[0]!;
    const payment = Transaction.from(Buffer.from(serialized)).instructions[0]!;
    const accounts = payment.keys.map((k) => k.pubkey.toBase58());

    // TransferChecked: [source, mint, destination, authority].
    expect(accounts[0]).toBe(associatedTokenAddress(MINT, SELF).toBase58());
    expect(accounts[1]).toBe(MINT.toBase58());
    expect(accounts[2]).toBe(TREASURY.toBase58());
    expect(accounts[3]).toBe(SELF.toBase58());
    expect(payment.keys[3]!.isSigner).toBe(true);

    // Decoded by hand so the assertion tests the encoding, not Buffer's helpers.
    expect(payment.data[0]).toBe(12); // TransferChecked, never a bare Transfer
    let amount = 0n;
    for (let i = 7; i >= 0; i--) amount = (amount << 8n) | BigInt(payment.data[1 + i]!);
    expect(amount).toBe(1_200n);
    expect(payment.data[9]).toBe(6);
  });

  it("never reaches the relayer", async () => {
    const relayer = { getFeePayer: jest.fn(), sendSigned: jest.fn() };
    const toll = makeToll();
    await makeWallet(toll, relayer).execute(1n, Keypair.generate().publicKey.toBase58(), {
      fee: { token: MINT.toBase58() },
    });
    expect(relayer.getFeePayer).not.toHaveBeenCalled();
    expect(relayer.sendSigned).not.toHaveBeenCalled();
  });

  it("throws a clear error when no toll client is configured", async () => {
    await expect(
      makeWallet(undefined).execute(1n, Keypair.generate().publicKey.toBase58(), {
        fee: { token: MINT.toBase58() },
      }),
    ).rejects.toThrow(/no `toll` client configured/);
  });
});

describe("CavosSolana — the fee field replaces `sponsored`", () => {
  it("defaults to the account paying its own way", async () => {
    const toll = makeToll();
    const wallet = makeWallet(toll);
    const sig = await wallet.execute(1n, Keypair.generate().publicKey.toBase58());
    expect(sig).toBe("selfSig");
    expect((toll.submit as jest.Mock)).not.toHaveBeenCalled();
  });

  it("honours the deprecated sponsored: true", async () => {
    const relayer = {
      getFeePayer: jest.fn().mockResolvedValue(TOLL_PAYER),
      sendSigned: jest.fn().mockResolvedValue("relayerSig"),
    };
    const wallet = makeWallet(undefined, relayer);
    await expect(
      wallet.execute(1n, Keypair.generate().publicKey.toBase58(), { sponsored: true }),
    ).resolves.toBe("relayerSig");
  });

  it("lets fee win over a contradicting sponsored", async () => {
    const relayer = { getFeePayer: jest.fn(), sendSigned: jest.fn() };
    const wallet = makeWallet(undefined, relayer);
    const sig = await wallet.execute(1n, Keypair.generate().publicKey.toBase58(), {
      fee: "self",
      sponsored: true,
    });
    expect(sig).toBe("selfSig");
    expect(relayer.sendSigned).not.toHaveBeenCalled();
  });
});
