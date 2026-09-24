import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { Keypair as SolanaKeypair, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { Account, Asset, Keypair, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { KeypairControlKey } from "../chains/stellar/WebCryptoControlKey";
import { generateMasterDEK, parseEd25519Seed, parseMasterDEK } from "../secret/dek";
import type { LocalDekInput } from "../secret/localDek";
import { unwrapDek } from "../secret/passkeyWrap";
import type { StoredPasskeyWrap } from "../registry/PasskeyWrapStore";
import { solanaSpendFromSeed } from "../signer/Ed25519SpendSigner";
import { prefixedMessageBytes } from "../signing";
import { createVaultHandler, serveVault } from "./host";
import { memoryLedger } from "./ledger";
import type { OverLimit } from "./limits";
import type { Line } from "./policy";
import { hash, typedData as typed } from "starknet";
import type { DeviceSigner } from "../signer/DeviceSigner";
import { bigIntTo32Bytes } from "../crypto/encoding";
import { outsideExecution } from "./fixtures";
import { VaultClient } from "./VaultClient";

const BLOCKHASH = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const params = { network: "solana-devnet", appSalt: "salt", userId: "u1", recovery: "none" as const };

function setup(confirm: () => Promise<boolean> = async () => true, overLimit: OverLimit = "ask") {
  const seed = parseEd25519Seed(randomBytes(32));
  const spend = solanaSpendFromSeed(seed);
  const stellarKey = Keypair.random();
  const asked: Line[][] = [];
  const networks: string[] = [];
  const starknetDevice = new RecordingDevice();
  const scopes: (string | undefined)[] = [];
  const dek = generateMasterDEK();
  const prf = new Uint8Array(32).fill(5);
  const dekReads: LocalDekInput[] = [];
  const wraps: StoredPasskeyWrap[] = [];
  const handle = createVaultHandler({
    appId: "app",
    backendUrl: "https://cavos.test",
    policy: {
      overLimit,
      limits: [
        { chain: "solana", asset: "SOL", perTx: "0.1", perDay: "0.5" },
        { chain: "stellar", asset: "XLM", perTx: "100", perDay: "500" },
        { chain: "starknet", asset: "ETH", perTx: "0.01", perDay: "0.05" },
      ],
    },
    ledger: memoryLedger(),
    confirm: async (lines, context) => {
      asked.push(lines);
      networks.push(context.network);
      return confirm();
    },
    passkey: () => ({
      enroll: async () => ({ credentialId: new Uint8Array(16).fill(1), secret: prf.slice() }),
      getSecret: async () => prf.slice(),
    }),
    passkeyWraps: () => ({
      list: async () => wraps,
      save: async (_userId, entry) => {
        wraps.push(entry);
      },
    }),
    readDek: async (input) => {
      dekReads.push(input);
      return parseMasterDEK(dek);
    },
    resolveSolana: async (input) => {
      scopes.push(input.keyScope);
      return { address: spend.address(), spend, isNewAccount: true };
    },
    loadStarknetDevice: async (keyId) => {
      scopes.push(keyId);
      return starknetDevice;
    },
    solanaNetwork: async () => "Solana Devnet",
    resolveStellar: async () => ({
      address: stellarKey.publicKey(),
      control: new KeypairControlKey(stellarKey),
      isNewAccount: false,
    }),
  });
  const channel = new MessageChannel();
  serveVault(channel.port2, handle);
  const client = VaultClient.fromPort(channel.port1);
  const close = () => {
    channel.port1.close();
    channel.port2.close();
  };
  return { client, asked, networks, scopes, stellarKey, starknetDevice, close, dek, prf, dekReads, wraps, spend };
}

/** Records what it was asked to sign; the signature itself is not under test here. */
class RecordingDevice implements DeviceSigner {
  signed: Uint8Array[] = [];
  async getPublicKey() {
    return { x: 7n, y: 11n };
  }
  async sign(bytes: Uint8Array) {
    this.signed.push(bytes);
    return { r: 1n, s: 2n, yParity: false };
  }
}

function solTransfer(from: string, lamports: number): Uint8Array {
  const owner = new PublicKey(from);
  const tx = new Transaction();
  tx.feePayer = owner;
  tx.recentBlockhash = BLOCKHASH;
  tx.add(SystemProgram.transfer({ fromPubkey: owner, toPubkey: SolanaKeypair.generate().publicKey, lamports }));
  return tx.serializeMessage();
}

describe("vault client and host", () => {
  it("signs a small Solana transfer without asking", async () => {
    const { client, asked, close } = setup();
    const { spend } = await client.connectSolana(params);
    const message = solTransfer(spend!.address(), 10_000_000);
    const signature = await spend!.signTransaction(message);
    expect(ed25519.verify(signature, message, spend!.publicKeyRaw())).toBe(true);
    expect(asked).toHaveLength(0);
    close();
  });

  it("serialises concurrent signatures so the daily limit holds", async () => {
    const { client, asked, close } = setup(async () => false);
    const { spend } = await client.connectSolana(params);
    const attempts = Array.from({ length: 8 }, () => spend!.signTransaction(solTransfer(spend!.address(), 90_000_000)));
    const results = await Promise.allSettled(attempts);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(5);
    expect(asked).toHaveLength(3);
    close();
  });

  it("asks before a transfer over the limit and signs once approved", async () => {
    const { client, asked, close } = setup(async () => true);
    const { spend } = await client.connectSolana(params);
    const message = solTransfer(spend!.address(), 2_000_000_000);
    const signature = await spend!.signTransaction(message);
    expect(ed25519.verify(signature, message, spend!.publicKeyRaw())).toBe(true);
    expect(asked[0][0]).toMatchObject({ kind: "send", amount: "2", asset: "SOL" });
    close();
  });

  it("refuses when the user rejects", async () => {
    const { client, close } = setup(async () => false);
    const { spend } = await client.connectSolana(params);
    await expect(spend!.signTransaction(solTransfer(spend!.address(), 2_000_000_000))).rejects.toThrow(/rejected/);
    close();
  });

  it("blocks without asking when the app's policy says so", async () => {
    const { client, asked, close } = setup(async () => true, "block");
    const { spend } = await client.connectSolana(params);
    await expect(spend!.signTransaction(solTransfer(spend!.address(), 2_000_000_000))).rejects.toThrow(/policy/);
    expect(asked).toHaveLength(0);
    close();
  });

  it("counts the day's spend across transactions", async () => {
    const { client, asked, close } = setup();
    const { spend } = await client.connectSolana(params);
    for (let i = 0; i < 5; i++) await spend!.signTransaction(solTransfer(spend!.address(), 90_000_000));
    expect(asked).toHaveLength(0);
    await spend!.signTransaction(solTransfer(spend!.address(), 60_000_000));
    expect(asked).toHaveLength(1);
    close();
  });

  it("signs messages with the Cavos prefix", async () => {
    const { client, close } = setup();
    const { spend } = await client.connectSolana(params);
    const message = new TextEncoder().encode("hello");
    const signature = await spend!.signMessage(message);
    expect(ed25519.verify(signature, prefixedMessageBytes(message), spend!.publicKeyRaw())).toBe(true);
    close();
  });

  it("signs a Stellar payment and asks before a signer change", async () => {
    const { client, asked, stellarKey, close } = setup();
    const { control } = await client.connectStellar({ ...params, network: "stellar-testnet" });
    const build = (op: ReturnType<typeof Operation.payment>) =>
      new TransactionBuilder(new Account(stellarKey.publicKey(), "1"), { fee: "100", networkPassphrase: Networks.TESTNET })
        .addOperation(op)
        .setTimeout(30)
        .build();

    const payment = build(Operation.payment({ destination: Keypair.random().publicKey(), asset: Asset.native(), amount: "1" }));
    const signature = await control!.signTransaction(payment.toXDR(), Networks.TESTNET);
    expect(stellarKey.verify(payment.hash(), Buffer.from(signature))).toBe(true);
    expect(asked).toHaveLength(0);

    const rotate = build(Operation.setOptions({ signer: { ed25519PublicKey: Keypair.random().publicKey(), weight: 1 } }));
    await control!.signTransaction(rotate.toXDR(), Networks.TESTNET);
    expect(asked).toHaveLength(1);
    close();
  });

  it("forgets an account on logout", async () => {
    const { client, close } = setup();
    const { spend } = await client.connectSolana(params);
    await client.forget("u1", "salt");
    await expect(spend!.signMessage(new Uint8Array([1]))).rejects.toThrow(/connect first/);
    close();
  });

  it("signs a Starknet outside execution over the hash it computes itself", async () => {
    const { client, asked, starknetDevice, close } = setup();
    const device = await client.connectStarknet({ ...params, network: "sepolia" });
    expect(device.publicKey).toEqual({ x: 7n, y: 11n });

    const account = "0x0123";
    const eth = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    const transfer = hash.getSelectorFromName("transfer");
    const small = outsideExecution([{ To: eth, Selector: transfer, Calldata: ["0xabc", "0x2386f26fc10000", "0x0"] }]);
    const signature = await device.accountSigner.signMessage(small, account);
    expect(signature).toHaveLength(5);
    expect(asked).toHaveLength(0);
    expect(starknetDevice.signed[0]).toEqual(bigIntTo32Bytes(BigInt(typed.getMessageHash(small, account))));

    const large = outsideExecution([{ To: eth, Selector: transfer, Calldata: ["0xabc", "0xde0b6b3a7640000", "0x0"] }]);
    await device.accountSigner.signMessage(large, account);
    expect(asked).toHaveLength(1);
    expect(asked[0][0]).toMatchObject({ kind: "send", amount: "1", asset: "ETH" });
    close();
  });

  it("files every key under the app that embedded the vault", async () => {
    const { client, scopes, close } = setup();
    await client.connectSolana(params);
    await client.connectStarknet({ ...params, network: "sepolia" });
    expect(scopes).toEqual(["app", "app|u1:salt"]);
    close();
  });

  it("shows the network the transaction is for, not the one the app named", async () => {
    const { client, networks, stellarKey, close } = setup();
    const { control } = await client.connectStellar({ ...params, network: "stellar-testnet" });
    const onMainnet = new TransactionBuilder(new Account(stellarKey.publicKey(), "1"), { fee: "100", networkPassphrase: Networks.PUBLIC })
      .addOperation(Operation.payment({ destination: Keypair.random().publicKey(), asset: Asset.native(), amount: "200" }))
      .setTimeout(30)
      .build();
    await control!.signTransaction(onMainnet.toXDR(), Networks.PUBLIC);
    expect(networks).toEqual(["Stellar Mainnet"]);
    await expect(control!.signTransaction(onMainnet.toXDR(), "Made-up network")).rejects.toThrow(/unknown Stellar network/);
    close();
  });
});

describe("vault passkeys", () => {
  const passkeyParams = { ...params, recovery: "passkey" as const };

  it("refuses to add a passkey before a native account is connected", async () => {
    const { client, wraps, close } = setup();
    await expect(client.enrollPasskey({ userId: "u1", appSalt: "salt" })).rejects.toThrow(
      "connect a Solana or Stellar wallet",
    );
    expect(wraps).toHaveLength(0);
    close();
  });

  it("stores the connected account's DEK, read under the app's scope, encrypted under the new passkey", async () => {
    const { client, dek, prf, dekReads, wraps, spend, close } = setup();
    await client.connectSolana(passkeyParams);
    await client.enrollPasskey({ userId: "u1", appSalt: "salt" });
    expect(dekReads).toEqual([
      { chain: "solana", userId: "u1", appSalt: "salt", address: spend.address(), keyScope: "app" },
    ]);
    expect(wraps).toHaveLength(1);
    expect(unwrapDek(wraps[0].wrap, prf, { appId: "app", userId: "u1" })).toEqual(parseMasterDEK(dek));
    close();
  });

  it("reports a passkey only once one was added", async () => {
    const { client, close } = setup();
    expect((await client.connectSolana(passkeyParams)).passkey).toBe(false);
    await client.enrollPasskey({ userId: "u1", appSalt: "salt" });
    expect((await client.connectSolana(passkeyParams)).passkey).toBe(true);
    close();
  });
});
