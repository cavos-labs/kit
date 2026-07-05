/**
 * End-to-end check on Stellar testnet for the classic-G multisig account.
 *
 * Proves the whole self-custodial path without any backend/registry/contract:
 *   1. deterministic `G…` address from identity,
 *   2. account creation (master weight-0 + control weight-1 + on-chain control-key
 *      envelope, DEK-sealed and ECIES-wrapped to this device),
 *   3. a native XLM payment signed ONLY by the envelope-unlocked control key,
 *   4. a fresh `connect` (returning user, same device key) that rebuilds the
 *      control key from the on-chain envelope and lands `status: "ready"`,
 *   5. a fresh `connect` with a DIFFERENT device key → `needs-device-approval`.
 *
 * Self-funded via friendbot (no relayer needed to exercise the account). Run:
 *   npx tsx scripts/stellar_classic_e2e.ts
 */
import { Keypair } from "@stellar/stellar-sdk";
import { CavosStellar } from "../src/chains/stellar/CavosStellar";
import { StellarAdapter } from "../src/chains/stellar/StellarAdapter";
import { LocalDeviceUnwrapKey } from "../src/chains/stellar/DeviceUnwrapKey";
import { deriveStellarAddress } from "../src/chains/stellar/keys";

const NETWORK = "stellar-testnet" as const;

async function fundFriendbot(pub: string) {
  const res = await fetch(`https://friendbot.stellar.org/?addr=${pub}`);
  if (!res.ok && res.status !== 400) throw new Error(`friendbot failed: ${res.status}`);
}

function ok(label: string, cond: boolean) {
  console.log(`${cond ? "✅" : "❌"} ${label}`);
  if (!cond) throw new Error(`assertion failed: ${label}`);
}

async function main() {
  const identity = { userId: `e2e-${Date.now()}`, appSalt: "classic-e2e" };
  const expectedAddress = deriveStellarAddress(identity);
  console.log("Deterministic G address:", expectedAddress);

  // Self-funded source (friendbot) that pays creation fees + seeds the account.
  const source = Keypair.random();
  console.log("Funding source", source.publicKey(), "via friendbot…");
  await fundFriendbot(source.publicKey());

  const deviceKey = LocalDeviceUnwrapKey.generate();

  // 1 + 2 + 3: create the account, then pay.
  const cavos = await CavosStellar.connect({
    network: NETWORK,
    identity,
    appSalt: identity.appSalt,
    deviceKey,
    sourceKeypair: source,
    startingBalance: 100_000_000n, // 10 XLM: this test piles on many devices/factors
  });
  ok("address matches deterministic derivation", cavos.address === expectedAddress);
  ok("isNewAccount on first connect", cavos.isNewAccount === true);
  ok("status ready after create", cavos.status === "ready");
  console.log("control (weight-1 signer):", cavos.controlAddress);

  const bal0 = await cavos.balance();
  console.log("balance after create (stroops):", bal0.toString());
  ok("account funded", bal0 > 0n);

  // Verify the master is really powerless: it must be weight 0 on-chain.
  const adapter = new StellarAdapter({ network: NETWORK });
  const acct = await adapter.server().loadAccount(cavos.address);
  const masterSigner = acct.signers.find((s) => s.key === cavos.address);
  ok("master weight is 0", masterSigner?.weight === 0);
  ok(
    "control is a weight-1 signer",
    acct.signers.some((s) => s.key === cavos.controlAddress && s.weight === 1),
  );

  const dest = Keypair.random();
  await fundFriendbot(dest.publicKey());
  const hash = await cavos.execute(2_000_000n, dest.publicKey()); // 0.2 XLM
  console.log("payment tx:", hash);
  ok("payment submitted", typeof hash === "string" && hash.length > 0);

  // 4: returning user on the SAME device — unlock control from the envelope.
  const again = await CavosStellar.connect({
    network: NETWORK,
    identity,
    appSalt: identity.appSalt,
    deviceKey,
    sourceKeypair: source,
  });
  ok("returning connect finds same address", again.address === cavos.address);
  ok("returning connect is not a new account", again.isNewAccount === false);
  ok("returning connect status ready (control unlocked)", again.status === "ready");
  ok("returning connect recovered same control key", again.controlAddress === cavos.controlAddress);

  // 5: a DIFFERENT device (no wrap slot) → needs approval.
  const otherDevice = LocalDeviceUnwrapKey.generate();
  const newDevice = await CavosStellar.connect({
    network: NETWORK,
    identity,
    appSalt: identity.appSalt,
    deviceKey: otherDevice,
    sourceKeypair: source,
  });
  ok("new device is gated needs-device-approval", newDevice.status === "needs-device-approval");

  // 5b: enroll recovery + passkey factors from the ready device.
  const recoveryCode = "amber basin arch cedar flame grove harbor ivory";
  const prf = crypto.getRandomValues(new Uint8Array(32)); // stands in for WebAuthn PRF
  await cavos.setupRecovery(recoveryCode);
  await cavos.enrollPasskey(prf);
  console.log("enrolled recovery + passkey factors");

  // 6: approve the pending new device using the RECOVERY code (no trip to old device).
  const okRecovery = await newDevice.approveThisDeviceWithRecovery(recoveryCode);
  ok("recovery approval submitted", typeof okRecovery === "string" && okRecovery.length > 0);
  ok("new device now ready", newDevice.status === "ready");
  ok("new device recovered same control key", newDevice.controlAddress === cavos.controlAddress);

  // new device can now sign silently on its own (re-connect via its device slot).
  const rejoined = await CavosStellar.connect({
    network: NETWORK,
    identity,
    appSalt: identity.appSalt,
    deviceKey: otherDevice,
    sourceKeypair: source,
  });
  ok("approved device unlocks silently on reconnect", rejoined.status === "ready");

  // 7: approve a THIRD device using the PASSKEY factor.
  const thirdDevice = LocalDeviceUnwrapKey.generate();
  const third = await CavosStellar.connect({
    network: NETWORK,
    identity,
    appSalt: identity.appSalt,
    deviceKey: thirdDevice,
    sourceKeypair: source,
  });
  ok("third device starts needs-approval", third.status === "needs-device-approval");
  await third.approveThisDeviceWithPasskey(prf);
  ok("third device ready via passkey", third.status === "ready");
  ok("third device same control key", third.controlAddress === cavos.controlAddress);

  console.log("\n🎉 classic-G e2e passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
