/**
 * E2E: CavosSolana driven WITHOUT a feePayer — the Cavos relayer sponsors.
 * Proves the seedless/gasless path: the user's device key holds no SOL, yet
 * initialize + add_signer succeed and the relayer (not the user) pays.
 *
 * Prereq: the relay harness running (cavos-web/scripts/relay_server.ts) against
 * devnet, with the program deployed. Run:
 *   npx ts-node scripts/solana_relayer_e2e.ts http://127.0.0.1:8787
 */
import { Connection, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { CavosSolana } from "../src/chains/solana/CavosSolana";
import { SolanaRelayer } from "../src/chains/solana/SolanaRelayer";
import type { DeviceSigner, DeviceSignature, DevicePublicKey } from "../src/signer/DeviceSigner";
import { bytesToBigInt } from "../src/crypto/encoding";

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
  const relayUrl = process.argv[2] ?? "http://127.0.0.1:8787";
  const network = "solana-devnet" as const;
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");

  // One device signer for this user; the relayer is injected (no feePayer!).
  const device = NodeDeviceSigner.random();
  const relayer = new SolanaRelayer({ baseUrl: relayUrl, appId: "e2e-app", network, connection });
  const feePayerPubkey = await relayer.getFeePayer();
  const beforeRelayer = await connection.getBalance(feePayerPubkey);

  const cavos = await CavosSolana.connect({
    network,
    identity: { userId: `relayer-e2e-${Date.now()}` },
    appSalt: "relayer-e2e",
    createSigner: async () => device,
    relayer, // ← no feePayer anywhere
  });

  console.log(`account: ${cavos.address}`);
  console.log(`status:  ${cavos.status}`);

  // add a second device signer, authorized by device1 — relayer pays the fee.
  const device2 = NodeDeviceSigner.random();
  const sig = await cavos.addSigner(await device2.getPublicKey());
  console.log(`✅ add_signer relayed: ${sig}`);

  const afterRelayer = await connection.getBalance(feePayerPubkey);
  const userBal = await connection.getBalance(new PublicKey(cavos.address));
  console.log(`relayer paid:   ${(beforeRelayer - afterRelayer) / LAMPORTS_PER_SOL} SOL`);
  console.log(`account rent:   ${userBal / LAMPORTS_PER_SOL} SOL (held by PDA, funded by relayer)`);

  const ok = cavos.status === "ready" && beforeRelayer - afterRelayer > 0;
  console.log(`\nVERDICT: ${ok ? "✅ gasless via relayer — no feePayer, user holds no SOL" : "❌"}`);
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
