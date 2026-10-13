# @cavos/kit

`@cavos/kit` is an **embedded Stellar wallet SDK**, **embedded Solana wallet**,
and **embedded Starknet wallet** for React Native and web. Device-native
self-custodial accounts: every chain spends with a native key derived from a
MasterDEK (a stark key on **Starknet**, Ed25519 on **Solana and Stellar**), with
no passkey popups and no Face ID / Touch ID prompts on signing. OAuth / email
authenticates the user; the registry names the wallet; the device key signs. On the web those keys live in the **Cavos vault**, an
iframe on a Cavos origin, so the integrator's page never holds one.

**Chains:** **Starknet, Solana, and Stellar** are implemented today. Starknet
uses the standard OpenZeppelin `AccountUpgradeable` account whose stark key is
HKDF of the MasterDEK. Solana and Stellar use **native Ed25519** accounts (a
system account and a classic `G…`) whose spend key is HKDF of the same MasterDEK. A passkey or the
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

1. **Authenticate** — OAuth (Google, Apple) or an emailed 9-character code resolves a stable `userId`.
2. **Registry lookup** — `(userId, appId, chain, network) → address`. If the
   user already has an address for this app + chain, they get that address. If
   not, this device claims one: HKDF of the MasterDEK on every chain.
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
| `status` | `"undeployed"` (first execute deploys), `"ready"` (this device holds the spend key), `"needs-device-approval"` (this device holds no spend key; restore it with the enclave or a passkey). |
| `CavosStarknet` | Native OpenZeppelin account. The stark key is HKDF of the MasterDEK; the address derives from the public key and the pinned `OZ_ACCOUNT_CLASS_HASH`. |
| `CavosSolana` | Native Ed25519 system account. Address is HKDF of the MasterDEK. Relayer is fee payer only. |
| `CavosStellar` / `StellarAdapter` | Classic `G…` account. With enclave or passkey, the same MasterDEK as Solana. Grandfathered accounts still use extra Horizon signers. |
| `VaultClient` | The page's side of the Cavos vault: mounts the iframe and hands out signers that forward whole payloads. |
| `SolanaRelayer` / `StellarRelayer` | Cavos gasless sponsor: co-signs as fee payer so the integrator holds no keypair. |
| `fee: { token }` | Solana only. The fee is settled in a token the user already holds, in the same transaction, so an account with no SOL still transacts. |
| `SocialRecoveryClient` | Verifies hardware attestation, binds a provider token to one session, encrypts directly to the enclave. |

## Passkeys

Signing up never asks for a passkey. After connect, call `enrollPasskeyDefault()`
from `useCavos()` to add one; it can then restore the wallet on another device,
on every chain. There is no on-chain approver and no recovery-code `add_signer`.

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
  await wallet.execute(calls); // gasless; signed invisibly by the account key
}
```

## Quickstart — Solana

The address **is** an Ed25519 system account (Phantom-shaped). The spend key is
HKDF of a MasterDEK (`cavos-ed25519-solana-v1`); it is not a PDA and not a
program account.

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
named fee payer, never who authorises the transfer — a co-signer cannot alter
the instructions it signs.

**`'self'` is the default on Solana**, unlike Starknet and Stellar where a
fresh account cannot deploy itself or meet the base reserve without help. The
account here is a plain system account: it is signer and fee payer at once, so
there was never a reason it could not pay its own way.

**`{ token }` needs nothing configured.** The fee is settled in that token in
the same transaction, so an account holding no SOL still transacts. The token
must be one the service accepts and the account must hold it.

`'self'` and `'sponsored'` work on every chain. `{ token }` is Solana only —
it is typed that way, so writing it against Stellar or Starknet does not
compile.

> `sponsored: true` / `false` still works as a deprecated alias for
> `fee: 'sponsored'` / `'self'`. `fee` wins if both are passed.

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
> Token-2022 / ATA. The token route enforces its own.

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

The key and address are pure functions of a seed, so you can drive the account
with starknet.js directly:

```ts
import { Account, RpcProvider, Signer } from "starknet";
import { starkKeyFromSeed, starkPublicKey, starknetAddressFromPublicKey } from "@cavos/kit/starknet";

const privateKey = starkKeyFromSeed(seed); // 32-byte HKDF output of the MasterDEK
const address = starknetAddressFromPublicKey(starkPublicKey(privateKey));
const account = new Account({ provider: new RpcProvider({ nodeUrl: "https://..." }), address, signer: new Signer(privateKey) });
```

The account is the OpenZeppelin `AccountUpgradeable` (`OZ_ACCOUNT_CLASS_HASH`),
deployed through the UDC with the public key as salt and constructor argument.

## How signing works

**Starknet:** The stark key signs the transaction hash with no user
interaction; the signature is the standard two-felt `[r, s]` the OpenZeppelin
account validates. `signMessage` signs SNIP-12 revision 1 typed data (domain
`Cavos` / `1`, primary type `Message`) and returns the typed data alongside the
signature, so a verifier can recompute the hash or call the account's
`is_valid_signature`. Rotating the account key (`set_public_key`) is refused,
because the key is derived from the DEK.

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

**Security model:** On the web every spend key lives in the Cavos vault (the Starknet stark
key in vault memory, Solana and Stellar Ed25519 keys as non-extractable `CryptoKey`s), where signing is silent within the
app's limits and needs the user's approval beyond them. A new device restores
the MasterDEK with the enclave or with a passkey the user added — signing up
never asks for a passkey.

## Hardware-isolated social recovery

Social recovery is **opt-in** per Cavos environment. The developer selects
exactly one provider in the dashboard (`google`, `apple`, or email code),
so the user is never shown a three-provider recovery selector.

The kit verifies **AWS Nitro Enclave** attestation, with measurements pinned in
the package (`DEFAULT_SOCIAL_RECOVERY_ATTESTATION`). The enclave:

- Runs inside a Nitro VM with no persistent storage, no SSH, no operator access.
- Verifies that the provider token (Google/Apple/email) was minted for this user
  within the last 5 minutes.
- Seals or unwraps the MasterDEK on every chain. It does not sign spends.

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
email restore. The enclave **seals the MasterDEK**. Every chain unwraps it on a
new device; none adds an on-chain recovery signer.

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
Anyone holding a synced passkey that was added can spend on every chain.

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
      modal={{ appName: "My App" }}
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

- ✅ Native OpenZeppelin `AccountUpgradeable` (`OZ_ACCOUNT_CLASS_HASH`). Stark key
  and address = HKDF(MasterDEK, appSalt).
- ✅ `CavosStarknet` — `connect`, `execute(calls)` with lazy sponsored deploy,
  `signTransaction`, `signMessage` (SNIP-12, `curve: "stark"`), `upgrade`.
- ✅ New device: enclave unwrap or a passkey wrap; no on-chain device list.
- ✅ SNIP-6 `is_valid_signature` + SNIP-9 `execute_from_outside_v2` (standard OZ).
- ✅ `CavosAuth` (hosted Google/Apple/email/OTP login).
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
