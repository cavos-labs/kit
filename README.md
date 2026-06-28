# @cavos/kit

Device-native, verifiable smart accounts. Users get a deterministic wallet bound
to their identity, controlled by **silent device signers** — non-extractable
secp256r1 (P-256) keys that live on the device and sign **invisibly** (no passkey,
no Face ID / Touch ID, no popups). OAuth / email is used only to derive the
address, never to sign. No exported keys, no MPC, no on-chain JWT/RSA.

**Chains:** **Starknet** and **Solana** are implemented today, behind a single
unified `Cavos.connect({ chain, network })` entry point. The API is
chain-configurable by design — Stellar (and others) will slot in behind the same
`ChainAdapter` interface.

> New package. Does **not** replace `@cavos/react` / `react-native` (legacy
> OAuth/session-key SDKs), which continue on the old flow.

## Install

```bash
npm install @cavos/kit
```

## Concepts

| Piece | Role |
|-------|------|
| `Cavos.connect` | Unified entry point: log in → derive deterministic address → create/load device key → auto-deploy → ready, gas-sponsored wallet. |
| `deriveAddressSeed` / `deriveAddressSeedSolana` | Stable `address_seed` from `{ userId, appSalt }`. Identity → wallet, device-independent. |
| `StarknetAdapter` / `SolanaAdapter` | Per-chain: compute the deterministic address, build deploy/initialize/add/remove calls, serialize signatures. |
| `WebCryptoSigner` | Browser silent device signer: non-extractable P-256 key in IndexedDB, no UI on sign. |
| `StarknetDeviceSigner` | Drop-in starknet.js `SignerInterface` backed by a device signer (advanced). |
| `SolanaRelayer` | Cavos gasless sponsor for Solana: co-signs as fee payer so the integrator holds no keypair. |
| `RecoveryClient` | Interface to the (non-custodial) backend for the email-approval multi-device flow (Starknet). |

## Quickstart — Starknet

One call logs the user in and returns a ready, deployed, gas-sponsored smart
account controlled by a silent device key. The user only sees the login.

```ts
import { Cavos, StaticIdentity } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "starknet",
  network: "testnet",                 // "testnet" (sepolia) | "mainnet"
  appSalt: "my-app",
  // Identity from your login (use CavosAuth for hosted Google/Apple/email, or
  // wrap your own userId with StaticIdentity)
  auth: new StaticIdentity({ userId: user.id, email: user.email }),
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,        // hosted registry + recovery
  paymasterApiKey: process.env.CAVOS_PAYMASTER_API_KEY!, // gas sponsor
});

console.log(wallet.address);          // deterministic; auto-deployed on first connect

if (wallet.chain === "starknet" && wallet.status === "ready") {
  await wallet.execute(calls);        // gasless; signed invisibly by the device key
}
```

`wallet` is a discriminated union (`Cavos | CavosSolana`); narrow on
`wallet.chain` before calling `execute`, since its signature differs per chain.

## Quickstart — Solana

Same unified entry point; pass `chain: "solana"`. Gas is sponsored by the Cavos
relayer (activated by `appId`) — no `paymasterApiKey` and no fee-payer keypair
needed.

```ts
import { Cavos, StaticIdentity } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "solana",
  network: "testnet",                 // -> solana-devnet ("mainnet" -> solana-mainnet)
  appSalt: "my-app",
  auth: new StaticIdentity({ userId: user.id, email: user.email }),
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID, // activates the gasless relayer
});

if (wallet.chain === "solana" && wallet.status === "ready") {
  const signature = await wallet.execute(1_000_000n, recipient); // lamports, base58 dest
  console.log(signature);
}
```

On Solana every guarded action (initialize, add/remove signer, execute) is a
two-instruction bundle pairing Solana's **native secp256r1 precompile** with the
Cavos `cavos-device-account` program instruction. The address is a deterministic
PDA derived from `deriveAddressSeedSolana` (`{ userId, appSalt }`).

```ts
// Arbitrary program calls (SPL transfers, swaps, staking):
import type { InstructionData } from "@cavos/kit";

if (wallet.chain === "solana" && wallet.status === "ready") {
  const instructions: InstructionData[] = [/* … SPL/swap instructions … */];
  await wallet.executeInstructions(instructions); // CPIs run with the PDA signing
}
```

> **Note:** `execute(amount, destination)` moves **lamports** (SOL); use
> `executeInstructions(instructions)` for arbitrary program calls. Sponsored
> `executeInstructions` is gated by the app's Solana program allowlist (dashboard
> → Solana Programs); targets outside the allowlist + safe set are rejected.

## Quickstart — low-level (Starknet, advanced)

If you want to drive the pieces yourself (own paymaster, custom deploy), use the
adapter + signer directly instead of `Cavos.connect`:

```ts
import {
  StarknetAdapter, WebCryptoSigner,
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

// 3. Build deploy/initialize/add/remove calls, then submit through your own
//    paymaster. Route signing through a standard starknet.js Account:
import { Account, RpcProvider } from "starknet";
import { StarknetDeviceSigner } from "@cavos/kit";

const provider = new RpcProvider({ nodeUrl: "https://api.cartridge.gg/x/starknet/sepolia" });
const snAccount = new Account(provider, address, new StarknetDeviceSigner(signer), "1");
await snAccount.execute(someCalls); // signed silently; DeviceAccount validates on-chain
```

`StarknetDeviceSigner` is a drop-in starknet.js `SignerInterface`, so it also
plugs into paymaster SDKs (AVNU) for gasless flows. The kit does **not** own gas
sponsorship in the low-level path — route execution through your paymaster of
choice.

## How signing works

On **Starknet**, the device key signs `sha256(tx_hash)` with no user interaction
(WebCrypto's ECDSA hashes the message internally). The signature is serialized
as `[r_low, r_high, s_low, s_high, y_parity]` — exactly what
`DeviceAccount.__validate__` decodes. The contract recomputes `sha256(tx_hash)`,
normalizes high-s, and recovers the secp256r1 signer. This 5-felt encoding is
covered by a cross-checked contract test (`test_sdk_signature_payload_authorized`
in `account-contracts/starknet`).

On **Solana**, each guarded action pairs the native `Secp256r1SigVerify`
precompile (which records the device's P-256 signature of a domain-separated
message) with the Cavos program instruction that consumes it. The fee payer is
not bound by the device signature, so the relayer co-signs without re-authorizing
the action.

**Security model:** the private key is non-extractable (never visible to JS) and
device-bound — non-custodial, no MPC, verified on-chain. Because signing is
silent there is no per-signature user-verification gate (unlike a biometric
passkey); this is the standard embedded-wallet trade-off. Multi-device + the
non-custodial recovery relay cover device loss.

## Status

### Starknet

- ✅ Silent secp256r1 device signer (`WebCryptoSigner`) + 5-felt signature
  serialization, cross-checked against the live contract.
- ✅ Deterministic address, deploy/initialize/add/remove call builders.
- ✅ `starknet.js` `Account` integration via `StarknetDeviceSigner`.
- ✅ **Proven on-chain (Sepolia):** silent device key signs a real STRK `approve`,
  the deployed DeviceAccount validates it ([tx](https://sepolia.starkscan.co/tx/0x51e0e961ee535bf3c45ea020b9c258aee544ed18aea57dbbc80767f8e86ab9e)).
- ✅ `Cavos.connect` orchestration: auth → device key → address → auto-deploy → execute.
- ✅ **Gasless proven on-chain (Sepolia):** relayer-paid `execute_from_outside_v2`,
  authorized solely by the silent device signature, executed a real STRK approve
  ([tx](https://sepolia.starkscan.co/tx/0x05ade4008f4ccbcfe4a7f016c61eb0eb591c8f696db3f5dad6f0db3ea3b5d2e6)).
- ✅ Contract SNIP-6 `is_valid_signature` + SNIP-9 `execute_from_outside_v2` (OZ SRC9 component).
- ✅ `CavosAuth` (hosted Google/Apple/email/OTP login, mirroring `@cavos/react`).
- ✅ Recovery client interface (non-custodial multi-device email-approval flow).
- 🚧 Cavos paymaster backend must register the new class hash (backend, out of repo).

### Solana

- ✅ `SolanaAdapter` — PDA derivation, the `[secp256r1 precompile, program]`
  instruction builders, low-S normalization, anchor discriminators.
- ✅ `CavosSolana` high-level client — `connect`, `execute(amount, destination)`,
  `executeInstructions(instructions)`, `addSigner`, `setupRecovery`, static
  `recover`; gasless by default via the relayer when `appId` is set.
- ✅ `executeInstructions` arbitrary CPI — the device key signs over a hash of the
  instruction set; the on-chain `execute` instruction invokes the CPIs with the
  PDA signing. Sponsored calls are gated by the app's program allowlist.
- ✅ `SolanaRelayer` — co-signs as fee payer for seedless/gasless execution
  (integrator holds no fee-payer keypair); self-funded `feePayer` fallback.
- ✅ Unit tests + end-to-end scripts (`scripts/solana_e2e.ts`,
  `scripts/solana_relayer_e2e.ts`).
- ✅ Recovery (`setupRecovery` / `recover`) — same self-custodial model as Starknet.

### Cross-chain / next

- ✅ Unified `Cavos.connect({ chain, network })` dispatcher with a `CavosWallet`
  discriminated union.
- 🚧 Recovery backend service + session keys (Phase 2).
- 🚧 Stellar adapter (planned).

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
