/**
 * End-to-end check: drive the deployed `cavos-device-account` program through the
 * SolanaAdapter, proving the adapter's instruction encoding (discriminators, PDA,
 * signed-message layout, precompile bundle) matches the on-chain program.
 *
 * Prereq: a local agave >= 3.1 validator with the program deployed and the payer
 * funded (see account-contracts/solana/README.md). Run:
 *   npx ts-node scripts/solana_e2e.ts [rpcUrl] [payerKeypair.json]
 */
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import * as fs from "fs";
import { SolanaAdapter } from "../src/chains/solana/SolanaAdapter";
import type { DeviceSigner, DeviceSignature, DevicePublicKey } from "../src/signer/DeviceSigner";
import { bytesToBigInt } from "../src/crypto/encoding";
import { deriveAddressSeedSolana } from "../src/identity";

/** Node device signer over a P-256 key (stands in for WebCryptoSigner/Secure Enclave). */
class NodeDeviceSigner implements DeviceSigner {
  constructor(private readonly priv: Uint8Array) {}
  static random() {
    return new NodeDeviceSigner(p256.utils.randomPrivateKey());
  }
  async getPublicKey(): Promise<DevicePublicKey> {
    const u = p256.getPublicKey(this.priv, false);
    return { x: bytesToBigInt(u.slice(1, 33)), y: bytesToBigInt(u.slice(33, 65)) };
  }
  async sign(message: Uint8Array): Promise<DeviceSignature> {
    const sig = p256.sign(sha256(message), this.priv, { lowS: false });
    return { r: sig.r, s: sig.s, yParity: sig.recovery === 1 };
  }
}

async function main() {
  const rpc = process.argv[2] ?? "http://127.0.0.1:8899";
  const payerPath = process.argv[3] ?? "../account-contracts/solana/.keys/payer.json";
  const conn = new Connection(rpc, "confirmed");
  const payer = Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(fs.readFileSync(payerPath, "utf8")))
  );

  const device1 = NodeDeviceSigner.random();
  const adapter = new SolanaAdapter({ connection: conn, signer: device1 });

  const addressSeed = deriveAddressSeedSolana({ userId: "e2e-user", appSalt: "e2e-app" });
  const pubkey1 = await device1.getPublicKey();
  const account = adapter.computeAddress(addressSeed, pubkey1);
  console.log(`adapter account PDA: ${account}`);

  // 1) initialize
  const initIx = adapter.buildInitialize(addressSeed, payer.publicKey.toBase58(), pubkey1);
  await sendAndConfirmTransaction(conn, new Transaction().add(initIx), [payer]);
  console.log("✅ initialize");

  // 2) add a second signer (adapter builds the precompile bundle, device1 authorizes)
  const device2 = NodeDeviceSigner.random();
  const pubkey2 = await device2.getPublicKey();
  const addIxs = await adapter.buildAddSigner(account, pubkey2);
  await sendAndConfirmTransaction(conn, new Transaction().add(...addIxs), [payer]);
  console.log("✅ add_signer (device1-authorized)");

  // 3) reads
  console.log(`   device1 authorized: ${await adapter.isAuthorizedSigner(account, pubkey1)}`);
  console.log(`   device2 authorized: ${await adapter.isAuthorizedSigner(account, pubkey2)}`);

  // 4) fund the PDA and run a device-signed transfer
  await sendAndConfirmTransaction(
    conn,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: new PublicKey(account),
        lamports: 0.05 * LAMPORTS_PER_SOL,
      })
    ),
    [payer]
  );
  const dest = Keypair.generate().publicKey;
  const amount = BigInt(0.01 * LAMPORTS_PER_SOL);
  const xferIxs = await adapter.buildExecuteTransfer(account, dest.toBase58(), amount);
  await sendAndConfirmTransaction(conn, new Transaction().add(...xferIxs), [payer]);
  const destBal = await conn.getBalance(dest);
  console.log(`✅ execute_transfer — destination balance: ${destBal} lamports`);

  const ok = (await adapter.isAuthorizedSigner(account, pubkey1)) && destBal === Number(amount);
  console.log(`\nVERDICT: ${ok ? "✅ SolanaAdapter drives the on-chain program end-to-end" : "❌ mismatch"}`);
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
