# @cavos/kit

`@cavos/kit` is an **embedded Stellar wallet SDK**, **embedded Solana wallet**,
and **embedded Starknet wallet** for React Native and web. Device-native
self-custodial accounts controlled by **silent device signers** — non-extractable
secp256r1 (P-256) keys that sign invisibly (no passkey popups, no Face ID /
Touch ID prompts). OAuth / email authenticates the user; the registry names the
wallet; the device key signs.

**Chains:** **Starknet, Solana, and Stellar** are implemented today. Starknet
and Solana use on-chain device-signer accounts. Stellar uses a classic `G…`
account whose control key is encrypted in the account's own data entries and
unlocked by an enrolled device, passkey, or recovery factor. All three are
available through the unified `Cavos.connect({ chains, defaultChain, network })`
entry point.

**Direction:** Cavos is an every-chain wallet layer. These three adapters are
the current implementation set, not the boundary of the product. New chains
join through a chain-native adapter and must pass the same SDK conformance,
security, and end-to-end validation before being advertised as available.

> `@cavos/kit` is the active SDK for new integrations. `@cavos/react` and its
> OAuth/JWT session-key flow are legacy and should only be maintained for
> existing integrations.

## Install

```bash
npm install @cavos/kit
```

## How connect works

1. **Authenticate** — OAuth, magic link, or OTP resolves a stable `userId`.
2. **Registry lookup** — `(userId, appId, chain) → address`. If the user already
   has an address for this app + chain, they get that address. If not, this
   device computes a candidate address from its fresh device key.
3. **Registry claim** — Insert-only: the first device to register wins. If
   another device raced ahead, this device's candidate is discarded and the
   winning address is returned.
4. **Lazy deploy** — The account is **never** deployed on connect. The first
   `execute()` call deploys + runs the user's operation atomically.
5. **Status** — `undeployed` (not on-chain yet), `ready` (deployed, this device
   authorized), or `needs-device-approval` (deployed, this device not yet
   authorized).

The registry is the source of truth for "this user + this app + this chain →
this address". Cavos holds the map and cannot spend; the device holds the key
and can sign without Cavos once it has cached the address.

## Quickstart

### Single-chain (small apps)

For apps that only need one chain, pass `chain`:

```ts
import { Cavos, StaticIdentity } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "solana",                   // "starknet" | "solana" | "stellar"
  network: "testnet",                // "testnet" | "mainnet"
  appSalt: "my-app",
  auth: new StaticIdentity({ userId: user.id, email: user.email }),
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,
});

console.log(wallet.address);         // from registry (first device names it)
console.log(wallet.status);          // "undeployed" | "ready" | "needs-device-approval"

// First execute deploys + runs your calls atomically
if (wallet.status === "undeployed" || wallet.status === "ready") {
  await wallet.execute(1_000_000n, recipient); // deploys if needed, then sends
}
```

### Multi-chain sessions

Configure multiple chains and a default chain. Connect resolves addresses for
all configured chains but never deploys on connect — deployment is always lazy.

```ts
const session = await Cavos.connect({
  chains: ["solana", "stellar"],     // chains to configure
  defaultChain: "stellar",           // must be in chains
  network: "testnet",
  appSalt: "my-app",
  auth: new StaticIdentity({ userId: user.id }),
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,
});

// session IS the default-chain wallet (for back-compat)
console.log(session.chain);          // "stellar" (the default)
console.log(session.address);        // the stellar address
console.log(session.status);         // "undeployed" | "ready" | "needs-device-approval"

// Access other configured chains without reconnecting
const solanaWallet = session.wallet("solana");
console.log(session.chainStatus("solana")); // status of solana wallet
console.log(session.chainAddress("solana")); // solana address

// Execute on any chain — deploys if needed
if (session.status === "ready" || session.status === "undeployed") {
  await session.execute(10_000_000n, dest);   // stellar payment
}
if (solanaWallet.status === "ready" || solanaWallet.status === "undeployed") {
  await solanaWallet.execute(1_000_000n, recipient); // solana payment
}
```

The session shape: `wallet.chain` discriminates the union (`Cavos | CavosSolana
| CavosStellar`), so narrow on it before chain-specific calls.

### React: switching chains without re-auth

In `CavosProvider`, configure `chains` and use `setChain()` to switch the active
chain without re-authenticating or remounting:

```tsx
<CavosProvider
  config={{
    appId,
    chains: ["solana", "stellar"],
    defaultChain: "stellar",
    network: "testnet",
    appSalt: "my-app",
  }}
  modal={{ appName: "My App" }}
>
  <App />
</CavosProvider>
```

```tsx
function App() {
  const { chain, setChain, wallet, session, configuredChains } = useCavos();

  return (
    <div>
      <p>Active chain: {chain}</p>
      <button onClick={() => setChain("solana")}>Switch to Solana</button>
      {/* wallet is now the Solana wallet; no login prompt, no new deploy */}
    </div>
  );
}
```

## Lazy deploy

**Connect never deploys.** Deployment happens lazily on the first `execute()`
call, combined atomically with the user's operation.

```ts
const wallet = await Cavos.connect({ chain: "starknet", ... });
console.log(wallet.status);          // "undeployed"
console.log(wallet.isDeployed);      // false

// Undeployed wallets CAN sign messages (local device key)
const sig = await wallet.signMessage("hello");

// First execute deploys + runs the call atomically
await wallet.execute(calls);         // one sponsored tx: deploy + calls
console.log(wallet.status);          // "ready"
```

**Honest limits:**

- The squat window is longer: an attacker can register an address in the
  registry until the user's first transaction, not just until their first
  connect.
- Recovery factors are not on-chain until that chain's first transaction.
- The first execute is heavier (deploy + init + factors + user calls).

## Undeployed signing

`signMessage` works on undeployed wallets. The signature comes from the local
device key — proving control of that key needs no on-chain state. This enables
sign-in-with-wallet flows before the user has transacted.

```ts
const wallet = await Cavos.connect({ ... });
if (wallet.status === "undeployed") {
  // Still works — signs with the local device key
  const { signature, publicKey, curve } = await wallet.signMessage("Sign in");
}
```

## Concepts

| Piece | Role |
|-------|------|
| `Cavos.connect` | Unified entry: auth → registry lookup/claim → device key → lazy deploy on first execute. |
| `WalletRegistry` | `(userId, appId, chain) → address`. Source of truth. Cavos holds the map; cannot spend. The device holds the key and can sign without Cavos once it has cached the address. |
| `appSalt` | Names this app's **device-key slot**, so the same user in two apps gets two device keys. Does **not** name the address (the registry does). |
| `status` | `"undeployed"` (first execute deploys), `"ready"` (deployed + authorized), `"needs-device-approval"` (deployed, device not authorized). |
| `StarknetAdapter` / `SolanaAdapter` | Per-chain: compute the address a new user's first device claims, build deploy/add/remove calls, serialize signatures. |
| `CavosStellar` / `StellarAdapter` | Classic Stellar `G…` accounts named by the first control key, encrypted control-key envelope, device/passkey/recovery unlock. |
| `WebCryptoSigner` | Browser silent device signer: non-extractable P-256 key in IndexedDB, no UI on sign. |
| `StarknetDeviceSigner` | Drop-in starknet.js `SignerInterface` backed by a device signer (advanced). |
| `SolanaRelayer` / `StellarRelayer` | Cavos gasless sponsor: co-signs as fee payer so the integrator holds no keypair. |
| `RecoveryClient` | Interface to the backend for the email-approval multi-device flow (Starknet/Solana). |
| `SocialRecoveryClient` | Verifies hardware attestation, binds a provider token to one session, encrypts directly to the enclave. |

## Enroll factors before deploy

Passkey and recovery enrollment can happen before the first deploy. The factors
are stored locally and included in the first deployment transaction:

```ts
const wallet = await Cavos.connect({ chain: "starknet", ... });

// Status is "undeployed" — no on-chain account yet
await wallet.enrollPasskey(passkey, params); // stores pending, no tx
await wallet.setupRecovery(code);            // stores pending, no tx

// First execute deploys + initializes + adds pending factors atomically
await wallet.execute(calls); // one sponsored transaction does it all
```

## Quickstart — Starknet

```ts
import { Cavos, StaticIdentity } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "starknet",
  network: "testnet",                // "testnet" (sepolia) | "mainnet"
  appSalt: "my-app",
  auth: new StaticIdentity({ userId: user.id, email: user.email }),
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,
  paymasterApiKey: process.env.NEXT_PUBLIC_CAVOS_PAYMASTER_API_KEY!, // required
});

// First execute deploys if needed
if (wallet.chain === "starknet") {
  await wallet.execute(calls); // gasless; signed invisibly by the device key
}
```

## Quickstart — Solana

Same unified entry point; pass `chain: "solana"`. Gas is sponsored by the Cavos
relayer (activated by `appId`) — no `paymasterApiKey` and no fee-payer keypair.

```ts
import { Cavos, StaticIdentity } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "solana",
  network: "testnet",                // -> solana-devnet ("mainnet" -> solana-mainnet)
  appSalt: "my-app",
  auth: new StaticIdentity({ userId: user.id, email: user.email }),
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID, // activates the gasless relayer
});

if (wallet.chain === "solana") {
  const signature = await wallet.execute(1_000_000n, recipient); // lamports
  console.log(signature);
}
```

On Solana every guarded action (initialize, add/remove signer, execute) pairs
Solana's **native secp256r1 precompile** with the Cavos `cavos-device-account`
program instruction. The address is a PDA of
`[b"cavos-account", app_namespace, first_device_pubkey_x]`, so `initialize` with
any other key derives a different account and cannot claim this one.

```ts
// Arbitrary program calls (SPL transfers, swaps, staking):
import type { InstructionData } from "@cavos/kit";

if (wallet.chain === "solana") {
  const instructions: InstructionData[] = [/* … SPL/swap instructions … */];
  await wallet.executeInstructions(instructions); // CPIs run with the PDA signing
}
```

> **Note:** `execute(amount, destination)` moves **lamports** (SOL); use
> `executeInstructions(instructions)` for arbitrary program calls. Sponsored
> `executeInstructions` is gated by the app's Solana program allowlist (dashboard
> → Solana Programs); targets outside the allowlist + safe set are rejected.

## Quickstart — Stellar

`CavosStellar` creates or loads a classic Stellar `G…` account. The address is
named by the first device's control key (a random Ed25519 keypair whose public
key IS the `G…` address). On a known device, the control key is unlocked
silently from the encrypted on-chain envelope.

**Key model (pending control):**

1. On a **new user**, the first device generates a random Ed25519 control key.
   Its public key becomes the `G…` address. The private key is wrapped with a
   device-bound P-256 key and sealed into the account's data entries.
2. On a **returning user**, the device unwraps the control key from the on-chain
   envelope using its P-256 key.
3. Until the account is created on-chain, the control key is held **pending**
   locally — `signMessage` works, but nothing is on Stellar yet.

```ts
import { Cavos, StaticIdentity } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "stellar",
  network: "testnet",                // "testnet" | "mainnet"
  appSalt: "my-app",
  auth: new StaticIdentity({ userId: user.id }),
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID, // optional sponsored relayer
});

// First execute creates the account + performs the payment
if (wallet.chain === "stellar") {
  await wallet.execute(1_000_000n, recipient); // 0.1 XLM in stroops
}
```

**Soroban contract calls:**

```ts
if (wallet.chain === "stellar" && wallet.status === "ready") {
  await wallet.invokeContract({
    contractId: "C...",
    method: "approve",
    args: [approverAddress, amount],
  });
}
```

**Signing externally-built XDR:**

```ts
// For APIs that return unsigned XDR (e.g. Trustless Work)
const signedXdr = await wallet.signXdr(unsignedXdr);
```

The relayer can sponsor account creation and fee-bump transactions but **never
holds the control key** and cannot authorize payments.

## Quickstart — low-level (Starknet, advanced)

If you want to drive the pieces yourself (own paymaster, custom deploy), use the
adapter + signer directly instead of `Cavos.connect`:

```ts
import {
  StarknetAdapter, WebCryptoSigner,
  appNamespace, DEVICE_ACCOUNT_CLASS_HASH,
} from "@cavos/kit";

// 1. Create/load the SILENT device key. No prompt, ever. This key NAMES the
//    address, so it has to exist before there is an address at all.
const signer = await WebCryptoSigner.loadOrCreate({ keyId: `${user.id}:my-app` });

// 2. The address a first device claims. A returning user's address comes from
//    your own registry instead — it cannot be re-derived from their login.
const classHash = DEVICE_ACCOUNT_CLASS_HASH.sepolia;
const address = new StarknetAdapter({ classHash }).computeAddress({
  namespace: appNamespace({ appId: "my-app-id" }),
  initialSigner: await signer.getPublicKey(),
});

// 3. Build deploy/add/remove calls, then submit through your own paymaster:
import { Account, RpcProvider } from "starknet";
import { StarknetDeviceSigner } from "@cavos/kit";

const provider = new RpcProvider({ nodeUrl: "https://..." });
const snAccount = new Account(provider, address, new StarknetDeviceSigner(signer), "1");
await snAccount.execute(someCalls); // signed silently; DeviceAccount validates on-chain
```

`StarknetDeviceSigner` is a drop-in starknet.js `SignerInterface`, so it plugs
into paymaster SDKs (AVNU) for gasless flows. The kit does **not** own gas
sponsorship in the low-level path — route execution through your paymaster.

## How signing works

**Starknet:** The device key signs `sha256(tx_hash)` with no user interaction
(WebCrypto's ECDSA). The signature is serialized as `[r_low, r_high, s_low,
s_high, y_parity]` — what `DeviceAccount.__validate__` decodes. The contract
recomputes `sha256(tx_hash)`, normalizes high-s, and recovers the secp256r1
signer.

**Solana:** Each guarded action pairs the native `Secp256r1SigVerify` precompile
with the Cavos program instruction. The fee payer is not bound by the device
signature, so the relayer co-signs without re-authorizing the action.

**Stellar:** The daily signing key is a random Ed25519 control key recovered
from an encrypted account envelope. The device's non-extractable P-256 key is
used for ECIES unwrapping, not as the Stellar transaction signature. The control
key signs the actual Stellar transaction.

**Security model:** The private key is non-extractable (never visible to JS) and
device-bound — non-custodial, no MPC, verified on-chain. Because signing is
silent there is no per-signature user-verification gate (unlike a biometric
passkey); this is the standard embedded-wallet trade-off. Multi-device + the
non-custodial recovery relay cover device loss.

## Hardware-isolated social recovery

Social recovery is **opt-in** per Cavos environment. The developer selects
exactly one provider in the dashboard (`google`, `apple`, or email magic link),
so the user is never shown a three-provider recovery selector.

The kit verifies **AWS Nitro Enclave** attestation, with measurements pinned in
the package (`DEFAULT_SOCIAL_RECOVERY_ATTESTATION`). The enclave:

- Runs inside a Nitro VM with no persistent storage, no SSH, no operator access.
- Verifies that the provider token (Google/Apple/email) was minted for this user
  within the last 5 minutes.
- Schedules a signer-addition on-chain; the account's timelock + cancellation
  logic is the final gate.

With React, provide independently pinned measurements if you run your own
enclave (otherwise the shipped constants are used):

```tsx
<CavosProvider
  config={{
    appId,
    chains: ["solana"],
    network: "testnet",
    appSalt: "my-app",
    // Turn on hardware-isolated recovery using the enclave Cavos operates
    socialRecovery: true,
    // Or pin your own enclave's measurements:
    // socialRecovery: {
    //   pcr0: ["sha384-hash-of-your-enclave-image"],
    // },
  }}
  modal={{ appName: "My App" }}
>
  <App />
</CavosProvider>
```

The provider automatically enrolls ready wallets after a fresh login and
recovers an unregistered device with the same configured provider. Starknet and
Solana restrict the enclave authority on-chain to scheduling one exact signer,
with nonce, expiry, cancellation, and optional timelock. Stellar seals only the
DEK (never the Ed25519 control seed) and rewraps it to the new device.

This is **hardware-isolated, non-custodial recovery**, not trustless recovery.
The approved workload digest, AWS Nitro/KMS, and image-upgrade policy remain in
the trust model.

## React Native / Expo

React Native is supported through the native entrypoint on **iOS 16+** and
**Android 9+**. It uses Secure Enclave / Android Keystore keys and therefore
requires a bare React Native app or an Expo development build (Expo Go cannot
load custom native modules).

```bash
npm install @cavos/kit expo-modules-core expo-web-browser expo-linking
```

For Expo, configure the plugin and rebuild the native app:

```json
{
  "expo": {
    "plugins": [["@cavos/kit", { "rpId": "app.example.com", "scheme": "myapp" }]]
  }
}
```

```tsx
import { CavosProvider, useCavos } from "@cavos/kit/react-native";

export function Root() {
  return (
    <CavosProvider
      config={{
        appId: "your-app-id",
        chains: ["solana", "stellar"],
        defaultChain: "solana",
        network: "testnet",
        appSalt: "your-stable-app-salt",
        redirectUri: "myapp://cavos-auth",
        rpId: "app.example.com",
      }}
      modal={{ appName: "My App", emailMode: "otp" }}
    >
      <App />
    </CavosProvider>
  );
}

function App() {
  const { openModal, wallet, setChain } = useCavos();
  return null;
}
```

Register `redirectUri` exactly in the app's **Callback URLs** in the Cavos
dashboard. Native passkeys also require:

- `https://<rpId>/.well-known/apple-app-site-association` with the iOS app ID.
- `https://<rpId>/.well-known/assetlinks.json` with the Android package and
  signing-certificate fingerprint.

The default key policy prefers Secure Enclave, StrongBox, or TEE and falls back
to an OS-protected non-exportable key. Set `minimumKeySecurity: "hardware"` to
reject that fallback. Stellar passkey recovery uses PRF when the credential
provider supports it; otherwise the SDK surfaces a recovery-code fallback.

`logout()` only clears the saved identity. To intentionally remove the local
device, call `deleteDeviceKeys(identity.userId + ":" + appSalt)`. Reinstalling
the application also creates a new device that must be approved or recovered.

## Status

### Starknet

- ✅ Silent secp256r1 device signer (`WebCryptoSigner`) + 5-felt signature
  serialization, cross-checked against the live contract.
- ✅ Registry-based address resolution; first device names the wallet.
- ✅ `starknet.js` `Account` integration via `StarknetDeviceSigner`.
- ✅ **Proven on-chain (Sepolia):** silent device key signs a real STRK `approve`,
  the deployed DeviceAccount validates it ([tx](https://sepolia.starkscan.co/tx/0x51e0e961ee535bf3c45ea020b9c258aee544ed18aea57dbbc80767f8e86ab9e)).
- ✅ **Gasless proven on-chain (Sepolia):** relayer-paid `execute_from_outside_v2`,
  authorized solely by the silent device signature ([tx](https://sepolia.starkscan.co/tx/0x05ade4008f4ccbcfe4a7f016c61eb0eb591c8f696db3f5dad6f0db3ea3b5d2e6)).
- ✅ Contract SNIP-6 `is_valid_signature` + SNIP-9 `execute_from_outside_v2`.
- ✅ `CavosAuth` (hosted Google/Apple/email/OTP login).
- ✅ Recovery client interface (non-custodial multi-device email-approval flow).
- ✅ Hardware-isolated social recovery via Nitro enclave.

### Solana

- ✅ `SolanaAdapter` — PDA derivation, `[secp256r1 precompile, program]`
  instruction builders, low-S normalization.
- ✅ `CavosSolana` high-level client — `connect`, `execute(amount, destination)`,
  `executeInstructions(instructions)`, `addSigner`, `setupRecovery`, static
  `recover`; gasless by default via the relayer.
- ✅ Registry-based address resolution; first device names the wallet.
- ✅ `SolanaRelayer` — co-signs as fee payer for seedless/gasless execution.
- ✅ Hardware-isolated social recovery via Nitro enclave.

### Stellar

- ✅ `CavosStellar` — classic `G…` account, address named by first control key.
- ✅ Encrypted on-chain control-key envelope with device-bound P-256 ECIES
  unlock, passkey PRF recovery, and offline recovery-code support.
- ✅ **WebCrypto non-extractable control key:** The Ed25519 control key is
  non-extractable in WebCrypto environments. XSS cannot call `exportKey` on the
  control key; signing remains available while the tab is open.
- ✅ Native XLM payments and Soroban contract invocation with auth-entry signing.
- ✅ `StellarRelayer` — optional fee-bump sponsorship and sponsored account
  reserves; the relayer is never a custodian.
- ✅ **Pending control:** Undeployed wallets can `signMessage` using the locally
  held control key before the account exists on-chain.

### Every-chain foundation

- ✅ Unified `Cavos.connect({ chains, defaultChain, network })` dispatcher with
  `CavosSession` methods.
- ✅ Multi-chain sessions: one login, N wallets. `setChain()` in React without
  remount.
- ✅ Lazy deploy: connect never deploys; first execute deploys + operates.
- ✅ Registry lookup-first address resolution.
- ✅ Unified chain exports include Starknet, Solana, and Stellar adapters.

## Demo

See the [Cavos docs](https://docs.cavos.xyz) for live examples and integration
guides.

## Develop

```bash
npm install
npm run type-check
npm test        # signature <-> contract payload compatibility
npm run build   # tsup -> dist (cjs + esm + d.ts)
```
