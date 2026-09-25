# @cavos/kit

`@cavos/kit` is an **embedded Stellar wallet SDK**, **embedded Solana wallet**,
and **embedded Starknet wallet** for React Native and web. Device-native
self-custodial accounts: **Starknet** authorizes a silent non-extractable
secp256r1 (P-256) device signer (no passkey popups, no Face ID / Touch ID
prompts). **Solana and Stellar** spend with native Ed25519 keys derived from a
MasterDEK. OAuth / email authenticates the user; the registry names the wallet;
the device key signs. On the web those keys live in the **Cavos vault**, an
iframe on a Cavos origin, so the integrator's page never holds one.

**Chains:** **Starknet, Solana, and Stellar** are implemented today. Starknet
uses an on-chain Cairo `DeviceAccount` authorized by a silent P-256 device
signer. Solana and Stellar use **native Ed25519** accounts (a system account
and a classic `G…`) whose spend key is HKDF of one MasterDEK. A passkey or the
attested enclave restores that DEK on a new device. All three are available
through `Cavos.connect({ chains, defaultChain, network })`.

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
2. **Registry lookup** — `(userId, appId, chain, network) → address`. If the
   user already has an address for this app + chain, they get that address. If
   not, this device claims one: Starknet from the fresh P-256 device key;
   Solana/Stellar from HKDF of the MasterDEK.
3. **Registry claim** — Insert-only: the first device to register wins. If
   another device raced ahead, this device's candidate is discarded and the
   winning address is returned.
4. **Lazy deploy (Starknet / Stellar)** — Those accounts are **never** created
   on connect. The first `execute()` deploys + runs the user's operation.
   **Solana** is a system account: `ready` once this device unwraps the spend
   key; fund it with lamports, then spend. There is no `initialize`.
5. **Status** — `undeployed` (Starknet/Stellar, not on-chain yet), `ready`
   (this device can sign), or `needs-device-approval` (this device has no wrap
   / is not a signer yet).

The registry is the source of truth for "this user + this app + this chain →
this address". Cavos holds the map and cannot spend; the device holds the key
and can sign without Cavos once it has cached the address.

## The Cavos vault

In the browser, every signing key (Solana, Stellar and Starknet) lives in the
vault: an iframe on `vault.cavos.xyz`, not in the integrator's page. The page
asks for signatures and gets signatures back; an XSS or a compromised
dependency on the integrator's site cannot take a key, and it cannot sign past
the app's limits without the user seeing it.

- **On by default** in `CavosProvider` when `appId` is set. Pass `vault: false`
  to keep keys in the page (not recommended), or `vault: { url }` to use
  another deployment. `Cavos.connect` takes the same `vault` option.
- **Register your origins.** The vault only loads for sites listed in the app's
  allowed web origins or callback URLs in the Cavos dashboard.
- **Limits are set in the dashboard** (app → Approvals), never in code, so the
  page cannot loosen them: per token, per transaction and per day, plus what
  happens over the limit (ask the user, block, or sign anyway).
- **Within the limits the vault signs silently.** Over them, or for anything
  that is not a transfer of a listed token (contract calls, signer changes), it
  shows its own approval modal with the amount, the destination, the app and
  the network the transaction is really for.
- **What the vault signs, it reads.** Signers hand it whole transactions,
  Soroban auth entries and Starknet typed data or invokes, never bare hashes,
  and the vault computes the hash itself.
- **React Native** has no iframe; keys stay in the platform's secure storage as
  before.

`@cavos/kit/vault` exports `startVaultHost` and `startVaultConfirm`, the two
pages Cavos serves at `/vault` and `/vault/confirm`, and `VaultClient` for
custom setups.

## Quickstart

### Single-chain (small apps)

For apps that only need one chain, pass `chain`:

```ts
import { Cavos } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "solana",                   // "starknet" | "solana" | "stellar"
  network: "testnet",                // "testnet" | "mainnet"
  appSalt: "my-app",
  identity: { userId: user.id, email: user.email },
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,
});

console.log(wallet.address);         // from registry (first device names it)
console.log(wallet.status);          // "undeployed" | "ready" | "needs-device-approval"

// First execute deploys + runs your calls atomically
if (wallet.status === "undeployed" || wallet.status === "ready") {
  await wallet.execute(1_000_000n, recipient); // deploys if needed, then sends
}
```

`identity` is the canonical way to pass the signed-in user. If you'd rather hand
the kit an auth provider that resolves the user itself, pass `auth` instead —
`StaticIdentity` wraps a known user, and any `AuthProvider` implementation works:

```ts
import { StaticIdentity } from "@cavos/kit";

auth: new StaticIdentity({ userId: user.id, email: user.email }),
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
  identity: { userId: user.id },
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

### React: keeping a sign-in to the tab

By default a sign-in with the built-in auth is kept in `localStorage`: the user
stays signed in across tabs and browser restarts. Set `persistSession: false`
to keep it in `sessionStorage` instead. It then survives a reload and the OAuth
redirect, and ends when the tab closes. An identity saved earlier in
`localStorage` is removed, so switching the option off also signs out users
who were already signed in.

```tsx
<CavosProvider config={{ appId, network: "testnet", appSalt: "my-app", persistSession: false }}>
```

The option is read when the provider mounts. Only the built-in auth uses it:
with the `identity` prop your own auth decides. Either way the device keys stay
on the device, so signing in again reconnects the same wallet silently.

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
| `appSalt` | Device-key slot **and**, on Solana/Stellar native, HKDF salt for the spend key. Never change it. The registry key is still `(userId, appId, chain, network)`. |
| `status` | `"undeployed"` (first execute deploys), `"ready"` (deployed + authorized), `"needs-device-approval"` (deployed, device not authorized). |
| `StarknetAdapter` | Computes the DeviceAccount address a first device claims, and builds deploy/add/remove calls. |
| `CavosSolana` | Native Ed25519 system account. Address is HKDF of the MasterDEK. Relayer is fee payer only. |
| `CavosStellar` / `StellarAdapter` | Classic `G…` account. With enclave or passkey, the same MasterDEK as Solana. Grandfathered accounts still use extra Horizon signers. |
| `VaultClient` | The page's side of the Cavos vault: mounts the iframe and hands out signers that forward whole payloads. |
| `WebCryptoSigner` | Silent device signer: non-extractable P-256 key in IndexedDB (the vault's, on the web), no UI on sign. |
| `StarknetDeviceSigner` | Drop-in starknet.js `SignerInterface` backed by a device signer (advanced). |
| `SolanaRelayer` / `StellarRelayer` | Cavos gasless sponsor: co-signs as fee payer so the integrator holds no keypair. |
| `TollClient` | Solana only. Fee payer that settles in a token the user already holds, in the same transaction, so an account with no SOL still transacts. |
| `RecoveryClient` | Email-approval multi-device relay (**Starknet**). Native Solana/Stellar restore the MasterDEK instead. |
| `SocialRecoveryClient` | Verifies hardware attestation, binds a provider token to one session, encrypts directly to the enclave. |

## Enroll factors before deploy

On **Starknet**, passkey and recovery enrollment can happen before the first
deploy. The factors are stored locally and included in the first transaction:

```ts
const wallet = await Cavos.connect({ chain: "starknet", ... });
await wallet.enrollPasskey(passkey, params);
await wallet.setupRecovery(code);
await wallet.execute(calls);
```

On **Solana and Stellar**, signing up never asks for a passkey. After connect,
call `enrollPasskeyDefault()` from `useCavos()` to add one; it can then restore
the wallet on another device. Native Solana has no on-chain approver and no
recovery-code `add_signer`.

## Quickstart — Starknet

```ts
import { Cavos } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "starknet",
  network: "testnet",                // "testnet" (sepolia) | "mainnet"
  appSalt: "my-app",
  identity: { userId: user.id, email: user.email },
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,
  paymasterApiKey: process.env.NEXT_PUBLIC_CAVOS_PAYMASTER_API_KEY!, // required
});

// First execute deploys if needed
if (wallet.chain === "starknet") {
  await wallet.execute(calls); // gasless; signed invisibly by the device key
}
```

## Quickstart — Solana

The address **is** an Ed25519 system account (Phantom-shaped). The spend key is
HKDF of a MasterDEK (`cavos-ed25519-solana-v1`); it is not a PDA and not a
P-256 program account.

```ts
import { Cavos } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "solana",
  network: "testnet",                // -> solana-devnet ("mainnet" -> solana-mainnet)
  appSalt: "my-app",                 // part of HKDF; never change it
  identity: { userId: user.id, email: user.email },
  appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,
});

if (wallet.chain === "solana") {
  const signature = await wallet.execute(1_000_000n, recipient); // lamports
  console.log(signature);            // the user's Ed25519 signed the message
}
```

### Who pays the fee

`fee` answers one question — who pays, and in what — so the three answers are
one field rather than flags that look independent and are not.

```ts
await wallet.execute(amount, dest);                            // the account pays, in SOL
await wallet.execute(amount, dest, { fee: 'sponsored' });      // the Cavos relayer pays
await wallet.execute(amount, dest, { fee: { token: USDC } });  // the user pays, in USDC
```

The account signs its own transaction in all three. What changes is who is
named fee payer, never who authorises the transfer — neither the relayer nor
Toll can alter the instructions they co-sign.

**`'self'` is the default on Solana**, unlike Starknet and Stellar where a
fresh account cannot deploy itself or meet the base reserve without help. The
account here is a plain system account: it is signer and fee payer at once, so
there was never a reason it could not pay its own way.

**`{ token }` routes through [Toll](https://toll.cavos.xyz)**, which is fee
payer and settles in that token in the same transaction — so an account holding
no SOL still transacts. It needs `tollUrl`:

```ts
const wallet = await Cavos.connect({
  chain: "solana",
  // ...
  tollUrl: "https://toll.cavos.xyz",
});
```

Omit it and that route is simply unavailable; the other two are unaffected.

> `sponsored: true` / `false` still works as a deprecated alias for
> `fee: 'sponsored'` / `'self'`. `fee` wins if both are passed.

`'self'` and `'sponsored'` work on every chain. `{ token }` is Solana only —
it is typed that way, so writing it against Stellar or Starknet does not
compile.

`connect` does not create the account on-chain. The address is `ready` on this
device as soon as the spend key is unwrapped. The account exists on Solana once
it holds lamports (fund it, then spend). There is no `initialize` instruction
and no `add_signer`.

```ts
import type { InstructionData } from "@cavos/kit";

if (wallet.chain === "solana") {
  const instructions: InstructionData[] = [/* SPL / swap ixs; user is the signer */];
  await wallet.executeInstructions(instructions);
}
```

> **Note:** `execute(amount, destination)` moves **lamports**. Both take the
> same `fee` option. On the sponsored route the app's Solana program allowlist
> applies (dashboard → Solana Programs) on top of System / SPL Token /
> Token-2022 / ATA; Toll runs its own.

## Quickstart — Stellar

`CavosStellar` creates or loads a classic Stellar `G…` account.

**With `deviceApproval: "enclave"` or a passkey** (the current path): the `G…`
address is HKDF of the same MasterDEK as Solana (`cavos-ed25519-stellar-v1`).
A new device unwraps that DEK; it does not add a second Horizon signer.

**Grandfathered accounts** (no enclave, no passkey at connect): the first device
minted a random control key whose public key *is* the `G…`. Extra devices still
need a passkey or recovery code as additional weight-1 Horizon signers.

```ts
import { Cavos } from "@cavos/kit";

const wallet = await Cavos.connect({
  chain: "stellar",
  network: "testnet",                // "testnet" | "mainnet"
  appSalt: "my-app",
  identity: { userId: user.id },
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

**Solana:** The spend key is Ed25519. It signs the Solana transaction message.
The relayer co-signs only as fee payer.

**Stellar:** The control key is Ed25519. On the native-DEK path it is derived
from the MasterDEK; on grandfathered accounts it is the first device's random
key. Protection varies by runtime:

- **Browser:** The control key is a non-extractable `CryptoKey` held by the
  Cavos vault, not the page. The page can ask for signatures; the vault signs
  within the app's limits and asks the user for anything beyond them.
- **React Native iOS:** Signing stays inside the native module when that path
  is used.
- **Node:** The caller handles the raw key; no WebCrypto isolation.

**Security model:** Starknet device keys are non-extractable P-256. Solana and
Stellar spend keys are non-extractable Ed25519 (`CryptoKey` in the browser). On
the web all of them live in the Cavos vault, where signing is silent within the
app's limits and needs the user's approval beyond them. A new device restores
the MasterDEK with the enclave or with a passkey the user added — signing up
never asks for a passkey.

## Hardware-isolated social recovery

Social recovery is **opt-in** per Cavos environment. The developer selects
exactly one provider in the dashboard (`google`, `apple`, or email magic link),
so the user is never shown a three-provider recovery selector.

The kit verifies **AWS Nitro Enclave** attestation, with measurements pinned in
the package (`DEFAULT_SOCIAL_RECOVERY_ATTESTATION`). The enclave:

- Runs inside a Nitro VM with no persistent storage, no SSH, no operator access.
- Verifies that the provider token (Google/Apple/email) was minted for this user
  within the last 5 minutes.
- On **Solana and Stellar**, seals or unwraps the MasterDEK. It does not sign
  spends.
- On **Starknet**, schedules a restricted on-chain signer-addition.

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

Set `deviceApproval: "enclave"` (or `socialRecovery: true`) for Google/Apple/
email restore. The enclave **seals the MasterDEK**. Solana and Stellar unwrap it
on a new device; they do not add an on-chain recovery signer. Starknet still
registers a restricted recovery authority that can only schedule `add_signer`.

`deviceApproval: "passkey"` is **one chain**. Signing up never asks for a
passkey: the MasterDEK is random. `enrollPasskeyDefault()` creates a passkey in
the vault and stores a copy of the DEK encrypted under it:

```
KEK  = HKDF-SHA256(passkey PRF, "cavos-passkey-dek-wrap-v1")
wrap = 0x01 || nonce || AES-256-GCM(KEK, DEK, aad = "appId:userId")
```

Cavos keeps the wrap (`/api/passkey-wraps`) and cannot open it: the PRF never
leaves the user's device. On a new device the vault asks for the passkey only
if a wrap exists, decrypts locally and checks the DEK derives the registered
address. A user can add several passkeys; any of them restores the wallet.
Anyone holding a synced passkey that was added can spend on Solana/Stellar.

On Starknet the passkey is an on-chain approver instead. On a new device the
auth modal shows "Verify it's you" when the account has one, and
`approveDeviceWithPasskey()` adds this device.

`secureStep` defaults to `'off'`. Set `'optional'` / `'required'` only if you
want the modal's built-in "Secure your account" screen.

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
reject that fallback. Native Solana/Stellar restore with enclave unwrap or a
passkey wrap. Grandfathered Stellar wallets still use a recovery-code extra
signer when PRF is unavailable.

`logout()` does **not** wipe everything. It clears the persisted identity and
the session token, and tells the vault to let go of the keys it had unlocked.
Stored keys (in the vault's IndexedDB on the web, the Secure Enclave / Keystore
on native) stay so reconnect is silent; deleting them is never the page's call,
because a wallet with no recovery factor would be lost with them. It does not sign
the user out of Google or Apple. To intentionally remove the local device on
React Native, call `deleteDeviceKeys(identity.userId + ":" + appSalt)`.
Reinstalling the application also creates a new device that must unwrap or be
approved.

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

- ✅ Native Ed25519 system account. Address = HKDF(MasterDEK, appSalt).
- ✅ `CavosSolana` — `connect`, `execute(amount, destination)`,
  `executeInstructions(instructions)`, `signMessage` (`curve: "ed25519"`).
- ✅ `SolanaRelayer` — fee payer only. No device-account program, no PDA.
- ✅ New device: enclave unwrap or a passkey wrap. `addSigner` / `CavosSolana.recover`
  are not used.

### Stellar

- ✅ `CavosStellar` — classic `G…` account.
- ✅ Native MasterDEK path (enclave / passkey) shares the DEK with Solana.
- ✅ Grandfathered per-device Horizon signers still load for older wallets.
- ✅ **Non-extractable control key in the vault:** On the web the Ed25519
  control key lives in the Cavos vault, outside the integrator's page.
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
- ✅ **Cavos vault:** web signing keys for every chain live on a Cavos origin,
  with per-app limits and approvals set in the dashboard.

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
