# @cavos/kit

Device-native, verifiable smart accounts. Users get a deterministic wallet bound
to their identity, controlled by **silent device signers** — non-extractable
secp256r1 (P-256) keys that live on the device and sign **invisibly** (no passkey,
no Face ID / Touch ID, no popups). OAuth / email is used only to derive the
address, never to sign. No exported keys, no MPC, no on-chain JWT/RSA.

**Phase 1: Starknet only.** The API is chain-configurable by design so Stellar
and Solana adapters slot in behind the same `ChainAdapter` interface later.

> New package. Does **not** replace `@cavos/react` / `react-native` (legacy
> OAuth/session-key SDKs), which continue on the old flow.

## Install

```bash
npm install @cavos/kit
```

## Concepts

| Piece | Role |
|-------|------|
| `deriveAddressSeed` | Stable `address_seed` from `{ userId, appSalt }`. Identity → wallet, device-independent. |
| `StarknetAdapter` | Computes the deterministic address, builds deploy/initialize/add/remove calls, serializes signatures. |
| `WebCryptoSigner` | Browser silent device signer: non-extractable P-256 key in IndexedDB, no UI on sign. |
| `StarknetDeviceSigner` | Drop-in starknet.js `SignerInterface` backed by a device signer. |
| `CavosAccount` | High-level facade tying identity + adapter + signer together. |
| `RecoveryClient` | Interface to the (non-custodial) backend for the email-approval multi-device flow. |

## Quickstart — high-level (Privy-like)

One call logs the user in and returns a ready, deployed, gas-sponsored smart
account controlled by a silent device key. The user only sees the login.

```ts
import { Cavos, StaticIdentity, CavosPaymaster } from "@cavos/kit";

const cavos = await Cavos.connect({
  network: "sepolia",
  appSalt: "my-app",
  // Identity from your login (Cavos-hosted auth lands here; or pass your own userId)
  auth: new StaticIdentity({ userId: user.id, email: user.email }),
  // Gas sponsor — deploy + execute are gasless
  sponsor: new CavosPaymaster({ network: "sepolia", apiKey: process.env.CAVOS_API_KEY! }),
});

console.log(cavos.address);        // deterministic; auto-deployed on first connect
await cavos.execute(calls);        // gasless; signed invisibly by the device key
```

> **Status:** `Cavos.connect` orchestration (auth → device key → address →
> auto-deploy → execute) is built. Fully-gasless execution needs the contract to
> add SNIP-6 `is_valid_signature` + SNIP-9 `execute_from_outside_v2` (tracked
> follow-up) and the Cavos paymaster to support the new class. The self-funded
> path below is proven on-chain today.

## Quickstart — low-level (Starknet)

```ts
import {
  CavosAccount, StarknetAdapter, WebCryptoSigner,
  deriveAddressSeed, DEVICE_ACCOUNT_CLASS_HASH,
} from "@cavos/kit";

// 1. Identity (from your OAuth/email login) derives the address. No device key
//    needed for this — the address depends only on identity + salt.
const identity = { userId: user.id, appSalt: "my-app" };
const classHash = DEVICE_ACCOUNT_CLASS_HASH.sepolia; // from deployments/sepolia.json
const address = new StarknetAdapter({ classHash }).computeAddress({
  addressSeed: deriveAddressSeed(identity),
});

// 2. Create/load the SILENT device key (keyed by the address). No prompt, ever.
const signer = await WebCryptoSigner.loadOrCreate({ keyId: address });

// 3. Build the account.
const adapter = new StarknetAdapter({ classHash, signer });
const account = new CavosAccount({ identity, adapter, signer });
console.log(account.address); // deterministic, pre-deploy

// 4. Onboarding: deploy + register first signer (route through your paymaster).
const calls = await account.buildOnboarding(); // [UDC deploy, initialize] — submit atomically

// 5. Add another device later (must be self-submitted by an existing signer).
const addCall = account.buildAddSigner(otherDevicePublicKey);

// 6. Submit transactions through a standard starknet.js Account.
import { Account, RpcProvider } from "starknet";
import { StarknetDeviceSigner } from "@cavos/kit";

const provider = new RpcProvider({ nodeUrl: "https://api.cartridge.gg/x/starknet/sepolia" });
const snAccount = new Account(provider, account.address, new StarknetDeviceSigner(signer), "1");
await snAccount.execute(someCalls); // signed silently; DeviceAccount validates on-chain
```

`StarknetDeviceSigner` is a drop-in starknet.js `SignerInterface`, so it also
plugs into paymaster SDKs (AVNU) for gasless flows. The kit does **not** own gas
sponsorship — route execution through your paymaster of choice.

## How signing works

The device key signs `sha256(tx_hash)` with no user interaction (WebCrypto's
ECDSA hashes the message internally). The signature is serialized as
`[r_low, r_high, s_low, s_high, y_parity]` — exactly what
`DeviceAccount.__validate__` decodes. The contract recomputes `sha256(tx_hash)`,
normalizes high-s, and recovers the secp256r1 signer. This 5-felt encoding is
covered by a cross-checked contract test (`test_sdk_signature_payload_authorized`
in `account-contracts/starknet`).

**Security model:** the private key is non-extractable (never visible to JS) and
device-bound — non-custodial, no MPC, verified on-chain. Because signing is
silent there is no per-signature user-verification gate (unlike a biometric
passkey); this is the standard embedded-wallet trade-off. Multi-device + the
non-custodial recovery relay cover device loss.

## Status (Phase 1)

- ✅ Silent secp256r1 device signer (`WebCryptoSigner`) + 5-felt signature
  serialization, cross-checked against the live contract.
- ✅ Deterministic address, deploy/initialize/add/remove call builders.
- ✅ `starknet.js` `Account` integration via `StarknetDeviceSigner`.
- ✅ **Proven on-chain (Sepolia):** silent device key signs a real STRK `approve`,
  the deployed DeviceAccount validates it ([tx](https://sepolia.starkscan.co/tx/0x51e0e961ee535bf3c45ea020b9c258aee544ed18aea57dbbc80767f8e86ab9e)).
- ✅ `Cavos.connect` orchestration: auth → device key → address → auto-deploy → execute.
- ✅ `CavosPaymaster` client + `Sponsor` interface (Cavos-hosted gasless).
- ✅ **Gasless proven on-chain (Sepolia):** relayer-paid `execute_from_outside_v2`,
  authorized solely by the silent device signature, executed a real STRK approve
  ([tx](https://sepolia.starkscan.co/tx/0x05ade4008f4ccbcfe4a7f016c61eb0eb591c8f696db3f5dad6f0db3ea3b5d2e6)).
- ✅ Contract SNIP-6 `is_valid_signature` + SNIP-9 `execute_from_outside_v2` (OZ SRC9 component).
- ✅ `CavosAuth` (hosted Google/Apple/email/OTP login, mirroring `@cavos/react`).
- ✅ Recovery client interface (non-custodial multi-device email-approval flow).
- 🚧 Cavos paymaster backend must register the new class hash (backend, out of repo).
- 🚧 Recovery backend service + session keys (Phase 2).

## Demo

A runnable end-to-end demo lives in `my-app/app/kit-demo` (Next.js): log in
(identity only), see the deterministic address, create the silent device key,
build onboarding calls, sign a tx with zero prompts, and walk the non-custodial
add-device flow. Run `npm run dev` in `my-app` and open `/kit-demo`.

## Develop

```bash
npm install
npm run type-check
npm test        # signature <-> contract payload compatibility
npm run build   # tsup -> dist (cjs + esm + d.ts)
```
