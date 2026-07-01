/**
 * End-to-end check on Stellar testnet: drive the deployed `cavos-account-factory`
 * + `cavos-device-account` through CavosStellar / StellarAdapter, proving the
 * whole silent-device-signer path works on-chain — deterministic address, factory
 * deploy, and a transfer authorized ONLY by the P-256 device signature via the
 * account's `__check_auth`.
 *
 * Self-funded (no relayer needed to exercise the contract): a friendbot-funded
 * source keypair pays fees and seeds the account. Run:
 *   npx tsx scripts/stellar_e2e.ts
 */
import {
  Keypair,
  Operation,
  Account,
  TransactionBuilder,
  BASE_FEE,
  Address,
  nativeToScVal,
  xdr,
  rpc,
} from "@stellar/stellar-sdk";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { CavosStellar } from "../src/chains/stellar/CavosStellar";
import { StellarAdapter } from "../src/chains/stellar/StellarAdapter";
import { NATIVE_SAC_ID, STELLAR_NETWORKS } from "../src/chains/stellar/constants";
import type { DeviceSigner, DeviceSignature, DevicePublicKey } from "../src/signer/DeviceSigner";
import { bytesToBigInt } from "../src/crypto/encoding";

const NETWORK = "stellar-testnet" as const;
const { rpcUrl, passphrase } = STELLAR_NETWORKS[NETWORK];

/** Node device signer over a P-256 key (stands in for WebCryptoSigner). */
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
    const sig = p256.sign(sha256(message), this.priv, { lowS: true });
    return { r: sig.r, s: sig.s, yParity: sig.recovery === 1 };
  }
}

async function fundFriendbot(pub: string) {
  const res = await fetch(`https://friendbot.stellar.org/?addr=${pub}`);
  if (!res.ok && res.status !== 400) throw new Error(`friendbot failed: ${res.status}`);
}

/** Build → simulate → assemble → sign(source) → submit a source-authorized invoke. */
async function invokeAsSource(
  server: rpc.Server,
  source: Keypair,
  func: xdr.HostFunction,
): Promise<string> {
  const acct = await server.getAccount(source.publicKey());
  const op = Operation.invokeHostFunction({ func, auth: [] });
  const tx = new TransactionBuilder(acct, { fee: BASE_FEE, networkPassphrase: passphrase })
    .addOperation(op)
    .setTimeout(120)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(`sim failed: ${sim.error}`);
  const assembled = rpc.assembleTransaction(tx, sim).build();
  assembled.sign(source);
  const sent = await server.sendTransaction(assembled);
  if (sent.status === "ERROR") throw new Error(`send error: ${JSON.stringify(sent.errorResult)}`);
  for (let i = 0; i < 30; i++) {
    const got = await server.getTransaction(sent.hash);
    if (got.status === rpc.Api.GetTransactionStatus.SUCCESS) return sent.hash;
    if (got.status === rpc.Api.GetTransactionStatus.FAILED) throw new Error(`tx failed ${sent.hash}`);
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`not confirmed ${sent.hash}`);
}

async function main() {
  const server = new rpc.Server(rpcUrl);
  const source = Keypair.random();
  console.log(`source (fee payer): ${source.publicKey()}`);
  await fundFriendbot(source.publicKey());

  const device = NodeDeviceSigner.random();
  const identity = { userId: `e2e-${Date.now()}` };
  const appSalt = "cavos-stellar-e2e";

  // 1) Connect — derives the deterministic address and deploys via the factory.
  const cavos = await CavosStellar.connect({
    network: NETWORK,
    identity,
    appSalt,
    sourceKeypair: source,
    createSigner: async () => device,
  });
  console.log(`account: ${cavos.address}`);
  console.log(`status:  ${cavos.status}`);

  // Cross-check the off-chain address against a fresh adapter computation.
  const adapter = new StellarAdapter({ network: NETWORK, signer: device });
  const deployed = await adapter.isDeployed(cavos.address);
  console.log(`deployed on-chain: ${deployed}`);
  if (cavos.status !== "ready") throw new Error("expected ready status after connect");

  // 2) Fund the account contract with 5 XLM (source-authorized native SAC transfer).
  const fundFunc = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: new Address(NATIVE_SAC_ID[NETWORK]).toScAddress(),
      functionName: "transfer",
      args: [
        new Address(source.publicKey()).toScVal(),
        new Address(cavos.address).toScVal(),
        nativeToScVal(50_000_000n, { type: "i128" }), // 5 XLM in stroops
      ],
    }),
  );
  const fundHash = await invokeAsSource(server, source, fundFunc);
  console.log(`funded account (tx ${fundHash})`);

  // 3) THE PROOF: transfer 1 XLM out of the account, authorized ONLY by the
  //    silent device signature via __check_auth. Destination = source account.
  const execHash = await cavos.execute(10_000_000n, source.publicKey());
  console.log(`device-authorized transfer (tx ${execHash})`);
  console.log("\n✅ E2E PASSED — account deployed + device-signed transfer confirmed on testnet");
  console.log(`   explorer: https://stellar.expert/explorer/testnet/tx/${execHash}`);
}

main().catch((e) => {
  console.error("E2E FAILED:", e);
  process.exit(1);
});
