#!/usr/bin/env node
// End-to-end proof on Starknet Sepolia: a SILENT secp256r1 device signer controls
// a deployed DeviceAccount and executes a real STRK `approve`, paying its own gas.
//
// Subcommands:
//   node e2e_sepolia.mjs pubkey
//       -> prints the device pubkey (x,y) + the felt calldata for `initialize`.
//   node e2e_sepolia.mjs approve <accountAddress> <spender> [amount]
//       -> signs an STRK approve with the device key and submits it (v3 / STRK fee).
//   node e2e_sepolia.mjs allowance <accountAddress> <spender>
//       -> reads the resulting allowance.
//
// The device account must already be deployed + initialized with this pubkey and
// funded with STRK (done via sncast in the runner).

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { Account, RpcProvider, num, uint256, hash, shortString } from "starknet";
import { StarknetDeviceSigner } from "../dist/index.mjs";

function to32(v) {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

const RPC = process.env.RPC_URL ?? "https://api.cartridge.gg/x/starknet/sepolia";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

// Fixed device "secure-enclave" key for a reproducible run.
const DEVICE_PRIV = 0x1a2b3c4d5e6f00112233445566778899aabbccddeeff00112233445566778899n;

function privBytes() {
  const hex = DEVICE_PRIV.toString(16).padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function devicePub() {
  const pt = p256.ProjectivePoint.BASE.multiply(DEVICE_PRIV).toAffine();
  return { x: pt.x, y: pt.y };
}

// A silent device signer (the kit's DeviceSigner interface) backed by noble.
const deviceSigner = {
  async getPublicKey() {
    return devicePub();
  },
  async sign(txHash) {
    const digest = sha256(txHash); // what the device key signs
    const sig = p256.sign(digest, privBytes()); // low-s, with recovery
    return { r: sig.r, s: sig.s, yParity: sig.recovery === 1 };
  },
};

function u256ToHexFelts(v) {
  const u = uint256.bnToUint256(v);
  return [num.toHex(u.low), num.toHex(u.high)];
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const provider = new RpcProvider({ nodeUrl: RPC });

  if (cmd === "pubkey") {
    const { x, y } = devicePub();
    const [xl, xh] = u256ToHexFelts(x);
    const [yl, yh] = u256ToHexFelts(y);
    console.log("pub_x:", num.toHex(x));
    console.log("pub_y:", num.toHex(y));
    console.log("initialize calldata:", [xl, xh, yl, yh].join(" "));
    return;
  }

  if (cmd === "allowance") {
    const [accountAddress, spender] = args;
    const res = await provider.callContract({
      contractAddress: STRK,
      entrypoint: "allowance",
      calldata: [accountAddress, spender],
    });
    console.log("allowance:", uint256.uint256ToBN({ low: res[0], high: res[1] }).toString());
    return;
  }

  if (cmd === "approve") {
    const [accountAddress, spender, amountStr] = args;
    const amount = BigInt(amountStr ?? "1000000000000000000"); // 1 STRK default
    const { low, high } = uint256.bnToUint256(amount);

    const account = new Account({
      provider,
      address: accountAddress,
      signer: new StarknetDeviceSigner(deviceSigner),
      cairoVersion: "1",
    });

    const call = {
      contractAddress: STRK,
      entrypoint: "approve",
      calldata: [spender, num.toHex(low), num.toHex(high)],
    };

    console.log("Estimating fee WITH validation (secp256r1 is heavy)…");
    // Default estimation uses SKIP_VALIDATE, which omits the ~27M-gas secp256r1
    // recovery in __validate__ and under-bounds the tx -> "Out of gas". Estimate
    // with validation included so the resource bounds actually fit.
    const fee = await account.estimateInvokeFee(call, { skipValidate: false });
    console.log("Submitting STRK approve, signed silently by the device key…");
    const { transaction_hash } = await account.execute(call, { resourceBounds: fee.resourceBounds });
    console.log("tx:", transaction_hash);
    console.log("starkscan:", `https://sepolia.starkscan.co/tx/${transaction_hash}`);
    const receipt = await provider.waitForTransaction(transaction_hash);
    const status = receipt.value?.execution_status ?? receipt.execution_status ?? "see starkscan";
    console.log("execution_status:", status);
    return;
  }

  if (cmd === "outside") {
    // Build a SNIP-9 OutsideExecution for an STRK approve, compute the OZ
    // SNIP-12 message hash, sign it with the device key, and print the calldata
    // for `execute_from_outside_v2` (submit via a relayer / paymaster).
    const [spender, amountStr] = args;
    const amount = BigInt(amountStr ?? "2000000000000000000");
    const { low, high } = uint256.bnToUint256(amount);

    const DOMAIN_TH = 0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210n;
    const OE_TH = 0x312b56c05a7965066ddbda31c016d8d05afc305071c0ca3cdc2192c3c2f1f0fn;
    const CALL_TH = 0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9n;
    const P = (arr) => BigInt(hash.computePoseidonHashOnElements(arr));

    const ANY_CALLER = BigInt(shortString.encodeShortString("ANY_CALLER"));
    const nonce = BigInt(args[2] ?? "0x42");
    const executeAfter = 0n;
    const executeBefore = 0xffffffffffn;
    const sel = BigInt(hash.getSelectorFromName("approve"));
    const calldata = [BigInt(spender), low, high];

    const callHash = P([CALL_TH, BigInt(STRK), sel, P(calldata)]);
    const callsHash = P([callHash]);
    const structHash = P([OE_TH, ANY_CALLER, nonce, executeAfter, executeBefore, callsHash]);
    const chainId = BigInt(await provider.getChainId());
    const domainHash = P([DOMAIN_TH, BigInt(shortString.encodeShortString("Account.execute_from_outside")), 2n, chainId, 1n]);
    const account = BigInt(process.env.ACCT);
    const msgHash = P([BigInt(shortString.encodeShortString("StarkNet Message")), domainHash, account, structHash]);

    // Device signs sha256(msgHash) — exactly what is_valid_signature verifies.
    const sig = await deviceSigner.sign(to32(msgHash));
    const sigFelts = [sig.r & ((1n << 128n) - 1n), sig.r >> 128n, sig.s & ((1n << 128n) - 1n), sig.s >> 128n, sig.yParity ? 1n : 0n];

    // Serde calldata: OutsideExecution { caller, nonce, after, before, calls } + signature span
    const cd = [
      ANY_CALLER, nonce, executeAfter, executeBefore,
      1n, BigInt(STRK), sel, BigInt(calldata.length), ...calldata,
      BigInt(sigFelts.length), ...sigFelts,
    ];
    console.log("msg_hash:", num.toHex(msgHash));
    console.log("calldata:", cd.map((f) => num.toHex(f)).join(" "));
    return;
  }

  console.error("unknown command. use: pubkey | approve | allowance | outside");
  process.exit(1);
}

main().catch((e) => {
  console.error("ERROR:", e?.message ?? e);
  process.exit(1);
});
