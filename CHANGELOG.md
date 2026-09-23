# Changelog

## 0.2.1

### Passkeys restore native wallets on a new device

A passkey added after sign-up now carries a Solana or Stellar wallet to another
device. Before, `enrollPasskeyDefault()` created a passkey that restored
nothing, and a new device never asked for it.

- **Signing up never asks for a passkey.** The MasterDEK is random, whatever
  `deviceApproval` says. A passkey only restores an account that exists.
- **`enrollPasskeyDefault()` stores a copy of the DEK encrypted under the
  passkey**, created in the vault's origin: `KEK = HKDF(PRF,
  "cavos-passkey-dek-wrap-v1")`, `AES-256-GCM(KEK, DEK, aad = "appId:userId")`.
  Cavos keeps the ciphertext at `/api/passkey-wraps` and cannot open it.
- **A new device asks for the passkey only if one was added**, decrypts in the
  vault and checks the DEK derives the registered address. Several passkeys per
  user work; any of them restores. Declining leaves the device signed in
  without the key.
- **`hasPasskey`** on Solana and Stellar reports whether a passkey was added,
  from the backend, on any browser.
- **Starknet:** on a new device with a passkey approver, the auth modal shows
  "Verify it's you" instead of finishing silently, and a send from an
  unauthorized device opens it with a clear message.
- **The enclave seals wallets created before the app used it.** A device that
  already holds the key seals the DEK at the next sign-in, so a wallet created
  on passkeys, or with the enclave off, becomes recoverable.

### Vault

- Approvals happen in the vault's sheet on every browser. Where the browser
  cannot tell whether the page covers the frame (Safari), Approve arms after a
  short delay instead of moving to a separate Cavos window.
- The passkey sheet asks for one thing: "Add a passkey" to create, "Verify it's
  you" to restore.
- The sheet header shows the Cavos mark only, and the vault iframe no longer
  shows a "Cavos" tooltip.

### Breaking

- Accounts whose DEK was derived from the passkey PRF (created with
  `connect({ passkey: true })` on 0.1.14 to 0.2.0) no longer restore with that
  passkey.
- The vault protocol adds `enrollPasskey` and `ConnectResult.passkey`. Deploy
  the vault host (cavos-web) with this version before apps use it.
- `@noble/ciphers` is now a direct dependency.

## 0.2.0

### The Cavos vault

Signing keys for Solana, Stellar and Starknet move out of the integrator's page
and into the vault, an iframe on a Cavos origin (`vault.cavos.xyz`). The page
asks for signatures; it never holds a key, so a script running on it can no
longer take one.

- **On by default** in `CavosProvider` when `appId` is set. `vault: false`
  turns it off; `vault: { url }` points at another deployment. `Cavos.connect`
  takes the same `vault` option.
- **Limits and approvals come from the dashboard**, per app (Approvals page),
  never from the page. Within the limits the vault signs silently. Over them,
  the app's rule applies: ask the user, block, or sign anyway.
- **The vault reads what it signs.** Solana messages, Stellar transactions and
  Soroban auth entries, Starknet outside executions and invokes. Transfers of
  known assets count against the limits, and so do Solana fees and token
  account rent. Anything it cannot read as a transfer (signer changes, unknown
  programs or contracts) is over the limit. The network shown to the user is
  the one in the payload, not the one the app named.
- **Keys are filed under the app id**, and an app must register the origins
  that may embed it. Keys created by an earlier vault build are not reused.
- **Approvals** happen in the vault's own modal. Where the browser cannot tell
  whether the page is covering it (no Intersection Observer v2), the decision
  moves to a top-level Cavos window. Passkeys fall back to that window too.
- **Legacy copies are retired.** After a vault connect, a Solana or Stellar
  key, device unwrap key or wrapped DEK left in the page's storage is deleted
  once it provably opens the same address. Starknet device keys created before
  the vault stay on-chain and in page storage.
- `@cavos/kit/vault` exports `startVaultHost` and `startVaultConfirm` for the
  pages that serve it, and `dist/vault-browser` ships them as standalone scripts.

### Breaking

- `Ed25519SpendSigner.sign` is now `signTransaction(message)` and
  `signMessage(message)`; `signMessage` applies the Cavos prefix itself.
- `ControlKey.sign` is now `signTransaction(xdr, networkPassphrase)`,
  `signAuthEntry(preimageXdr)` and `signMessage(message)`.
- `StarknetAdapter.signMessageRaw(prefixedBytes)` is now
  `signMessage(message)`, which prefixes.
- `ConnectStellarOptions.deviceKey` is optional.
- `logout()` releases the vault's unlocked keys; it no longer deletes stored ones.

## 0.1.14

### Native Ed25519 + enclave MasterDEK

Solana is a native system account (Ed25519), not a PDA. Spend signs the chain
message; the relayer is only the fee payer. The same MasterDEK derives Solana
and Stellar keys, so one enclave enroll covers a multi-chain session.

- **Connect does not prompt for a passkey.** Passkey is opt-in:
  `enrollPasskeyDefault()` after login, `approveDeviceWithPasskey()` on a new
  device (`connect(id, { passkey: true })`).
- **Enclave enroll is no longer skipped** when this device already has a local
  wrap. A previous connect that claimed the address and then failed to seal left
  the Mac able to spend and a new phone with `not_enrolled`. Reconnect reseals;
  enroll is idempotent once the wrap exists.
- **Identity lookup** (`provider` + `subject`) finds a `dek_sealed` enrollment
  so a second chain or device unwraps instead of minting another DEK.
- **Native Stellar** matches Solana: `approveDeviceWithPasskey()` reconnects
  with `{ passkey: true }`. `setupRecovery` is a no-op; `approveThisDeviceWithPasskey`
  / `approveThisDeviceWithRecovery` throw. Grandfathered Horizon extras still
  load for older wallets.

## 0.1.12

### Seed-lifetime hardening

No public API changes.

**Stellar browser (WebCrypto):** `CavosStellar` no longer keeps the raw control seed (`_controlSeed`) on the instance. The spend path imports the seed into WebCrypto as a non-extractable Ed25519 `CryptoKey` and signs via `crypto.subtle.sign`. XSS cannot call `exportKey` on the imported key. XSS can still call `sign` or `execute` while the tab is unlocked; silent spend remains unchanged.

Account creation still unwraps the seed momentarily to write the `cv:ct` envelope to the ledger, then wipes the scalar. The DEK may remain in-session for passkey or recovery factor enrollment.

**React Native iOS:** `unwrapControlAndSign` keeps the seed and DEK inside the native module. Only the 64-byte Ed25519 signature crosses the JS bridge. Keychain protection class is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. No Face ID prompt.

**Android:** Native `unwrapControlAndSign` is not included in this release; the existing JS-side path continues.

**Scope:** Classic `G…` accounts only. No C-account (Soroban contract account). No MPC.

## 0.1.11

### Registry lookup without a login token

After OAuth, `CavosProvider` stripped `cavos_auth_code` from the URL and then
silent-reconnected the previous localStorage identity in the same tick. That
reconnect called `GET /api/wallets` with no Bearer token and failed with
`Invalid user token` (401).

- **`HttpWalletRegistry.lookup`** skips the fetch when there is no login token
  (`registry lookup skipped: no login token`). HTTP errors include the response
  body. `resolveAddress` already falls back to the address cache when lookup
  throws.
- **`CavosProvider`** marks the OAuth callback in flight *before* cleaning the
  URL, so silent reconnect does not race the code exchange.

## 0.1.10

### Multi-chain sessions

One login, N wallets. `Cavos.connect({ chains, defaultChain })` returns a session
containing wallets for all configured chains. The session IS the default-chain
wallet (for back-compat), augmented with methods to access other chains:

```ts
const session = await Cavos.connect({
  chains: ["solana", "stellar"],
  defaultChain: "stellar",
  network: "testnet",
  ...
});

session.chain;               // "stellar"
session.wallet("solana");    // CavosSolana
session.chainStatus("solana");
session.chainAddress("solana");
```

**React:** `useCavos().setChain("solana")` switches the active chain without
re-authenticating or remounting.

### Lazy deploy

Connect **never** deploys. The first `execute()` call on an undeployed account
deploys + performs the user operation atomically. Status is `"undeployed"` until
then.

```ts
const wallet = await Cavos.connect({ ... });
wallet.status;           // "undeployed"
await wallet.execute(calls); // deploys + runs
wallet.status;           // "ready"
```

### Undeployed signing

`signMessage` works on undeployed wallets. The signature comes from the local
device key — no on-chain state needed. Enables sign-in-with-wallet flows before
the user has transacted.

### Registry lookup-first

The address is named by the **registry**, not derived from identity. The first
device that successfully registers claims the address. Returning logins get that
same address from the registry. This fixes the second-wallet bug where two
devices racing to connect could each compute their own address.

The registry model:
- `(userId, appId, chain) → address`
- Cavos holds the map and cannot spend
- The device holds the key and can sign without Cavos once it has cached the
  address

`appSalt` now names the **device-key slot**, not the address.

### Stellar pending control

Stellar classic `G…` accounts hold the control key **pending** locally before
the account exists on-chain. `signMessage` works immediately after connect (the
Ed25519 control key is already generated and imported into WebCrypto).

The control key is non-extractable in WebCrypto environments — XSS cannot call
`exportKey` on it; signing remains available while the tab is open.

### Auth forwarded to connectors

The `auth` provider (login token) is now forwarded to every chain connector, so
the registry lookup authenticates the end user properly across all configured
chains.

### Passkey approval at login

On passkey-based flows, the device is authorized at login rather than at the
first action. The passkey gesture is local and instant, so waiting buys nothing
and leaves the session in a state that cannot sign.

### Session-wide passkey enrollment

`enrollPasskeyDefault()` creates one credential and registers it across all
configured chains (as an on-chain approver on Starknet/Solana, as the DEK factor
on Stellar).

### Other fixes

- Fixed: a funded Solana address (e.g. from friendbot) is not a deployed wallet.
- Fixed: the selected chain is kept inside the configured set when the config
  changes.
- Fixed: `chainStatus` and `chainAddress` throw if the chain is not configured.
- Fixed: the auth modal finishes on an undeployed wallet (no longer waits for
  deploy).
- Fixed: the recovery credential is not burned on an undeployed wallet.
- Fixed: the login token is sent on device routes, not the recovery session.
- Fixed: a brand-new wallet is no longer treated as one being recovered.
