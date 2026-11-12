---
name: cavos-stellar
description: Add a Cavos embedded wallet to a Stellar web or React Native app with @cavos/kit. Users sign in with Google, Apple, GitHub, Telegram, or an email code and get a classic G account with no seed phrase and no browser extension. Covers the React provider and hooks, lazy account creation, sponsored XLM reserves and fees, XLM payments, USDC-style trustlines, Soroban contract calls, signing an unsigned XDR from your backend, message signing, and device restore. Use when a Stellar app needs wallets for users who do not have one.
user-invocable: true
argument-hint: '[cavos task]'
---

# Cavos: embedded Stellar wallets

Cavos (`@cavos/kit`) gives each user a classic Stellar `G…` account inside your app. The user signs in
with Google, Apple, GitHub, Telegram, or an email code. The account key is derived from a per-user
MasterDEK on the user's device, so there is no seed phrase and no extension. The Cavos relayer
sponsors the account's XLM reserves and pays fees, so the user never needs to hold lumens.

The same package also ships Solana and Starknet adapters. This skill covers Stellar only.

- Docs: https://docs.cavos.xyz/docs/stellar (agent index: https://docs.cavos.xyz/llms.txt)
- Package: https://www.npmjs.com/package/@cavos/kit
- Dashboard (app ID, gas, callback URLs): https://cavos.xyz/dashboard

## When to use this skill

- The app needs Stellar accounts for users who do not have a wallet
- Onboarding must be gasless: the app sponsors reserves and fees
- The account must be a plain classic `G…` that any Stellar tool, exchange, or anchor understands
- The same account must also sign Soroban `require_auth` entries (escrows, marketplaces, DeFi)

## When NOT to use this skill

- The user already has Freighter or another extension wallet: use Stellar Wallets Kit
- You need a Soroban contract account (`C…`) with on-chain policies: use Smart Account Kit
- Server-side signing for your own treasury: Cavos keys belong to end users, not your backend

## Install

```bash
npm install @cavos/kit
```

Create an app in the dashboard and take its App ID. Add your exact origin under
**Dashboard → App → Settings → Callback URLs** (scheme, host, and path; no wildcards, no trailing
slash). Fund Stellar gas under **Dashboard → Gas → Stellar** before using mainnet.

## Mental model

| Piece | What it does | What it cannot do |
| --- | --- | --- |
| MasterDEK | Per-user secret. The `G…` key is HKDF of it (`cavos-ed25519-stellar-v1`). | |
| Device | Holds the Ed25519 account key and signs. | |
| Cavos vault (web, on by default with `appId`) | An iframe on a Cavos origin, running in the user's browser, that keeps the key in its IndexedDB as a non-extractable WebCrypto key. Your page asks it for signatures, within the limits set in the dashboard. | Your page never reads the key. |
| Relayer (`appId`) | Fee payer and reserve sponsor: it signs only as the sponsor or the fee-bump source. | It cannot authorize the account's own operations or move its funds. |
| Enclave (optional) | AWS Nitro enclave that holds a sealed copy of the MasterDEK, opens it only inside the enclave, and re-encrypts it to a new device of the same signed-in identity. | The enclave does not sign transactions. Because it opens the MasterDEK during restore, it is part of the trust model. |
| Passkey (optional) | Stores an encrypted copy of the MasterDEK. | It is not 2FA. Anyone holding the synced passkey can open the wallet. |

Key storage depends on the runtime:

- Browser: inside the Cavos vault, as a non-extractable WebCrypto key.
- React Native: in the OS keystore (Secure Enclave / Keychain, Android Keystore) through the native module.
- Node: there is no default. You supply the key and persist it yourself.

## Setup (React / Next.js)

The provider is client-only. In Next.js App Router, put `'use client'` at the top of the file that
renders it and of every component that calls `useCavos()`.

```tsx
'use client';
import { CavosProvider } from '@cavos/kit/react';

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <CavosProvider
      config={{
        appId: process.env.NEXT_PUBLIC_CAVOS_APP_ID,
        chains: ['stellar'],
        network: 'testnet', // 'testnet' | 'mainnet'
        appSalt: 'my-app', // HKDF salt. Never change it after users connect.
        socialRecovery: true, // restore on a new device by signing in again
        deviceApproval: 'enclave',
      }}
      modal={{ appName: 'My App', theme: 'light' }}
    >
      {children}
    </CavosProvider>
  );
}
```

```tsx
'use client';
import { useCavos } from '@cavos/kit/react';

export function WalletButton() {
  const { isAuthenticated, isLoading, address, openModal, logout } = useCavos();
  if (isLoading) return null;
  if (!isAuthenticated) return <button onClick={openModal}>Sign in</button>;
  return <button onClick={logout}>{address}</button>;
}
```

To use your own auth instead of the Cavos modal, pass `identity={{ userId, email }}` to the provider.
Derive `userId` from something that never changes.

## Get the Stellar wallet

```ts
const { wallet } = useCavos();
if (wallet?.chain !== 'stellar') return;
wallet.address; // G…
wallet.status; // 'undeployed' | 'ready' | 'needs-device-approval'
```

| Status | Meaning |
| --- | --- |
| `undeployed` | Address is known, the account does not exist on-chain yet. |
| `ready` | The account exists and this device can sign. |
| `needs-device-approval` | The user has a wallet, but this device holds no key yet. Restore with an enclave sign-in or `approveDeviceWithPasskey()`. |

Connecting never creates the account. The first `execute` creates it (sponsored), then runs the payment.

## Actions

```ts
// Native XLM payment, amount in stroops (1 XLM = 10_000_000n). Sponsored by default.
const hash = await wallet.execute(10_000_000n, 'GDEST…');

// Pay the fee from the account's own XLM instead of the relayer.
await wallet.execute(10_000_000n, 'GDEST…', { fee: 'self' });

// Balances
const stroops = await wallet.balance();
const usdc = await wallet.tokenBalance({ code: 'USDC', issuer: 'GA5ZSE…KZVN' }); // "0" if no trustline

// Trustline (the trustline reserve is sponsored). Needs status 'ready'.
await wallet.addTrustline({ code: 'USDC', issuer: 'GA5ZSE…KZVN' });

// Soroban call. This account signs only its own require_auth entry. Needs status 'ready'.
await wallet.invokeContract({ contractId: 'C…', method: 'approve_milestone', args: [0, wallet.address] });

// Your backend built the transaction: sign the unsigned XDR, do not submit.
const signedXdr = await wallet.signXdr(unsignedXdr);

// Off-chain message signature. Works while undeployed.
const { signature, publicKey, curve } = await wallet.signMessage('hello'); // curve: 'ed25519'
```

Circle USDC on mainnet is `USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`.

To let users pay reserves and fees in USDC instead of sponsored XLM, use `@cavos/reserve` and sign
with `wallet.signXdr`. See https://docs.cavos.xyz/docs/reserve.

## Gotchas

- **`appSalt`, `appId`, and `userId` are permanent.** Changing any of them silently moves every user
  to a new, empty wallet. Nothing errors.
- **A sponsored account holds 0 XLM.** The relayer sponsors reserves, so the account starts with no
  lumens. An XLM payment needs XLM in the account first. Trustlines and Soroban calls do not.
- **`addTrustline` and `invokeContract` need `status === 'ready'`.** Only `execute` creates the account.
- **Do not gate execution on `isReady`.** `undeployed` can execute; only `needs-device-approval` blocks.
- **Second browser or device:** the user lands on `needs-device-approval` until the device restores the
  MasterDEK (enclave sign-in, or `approveDeviceWithPasskey()` if a passkey was added).
- **`redirect_uri is not registered`:** the exact origin is missing from Callback URLs. An empty list
  rejects everything.
- **`signMessage` adds a Cavos domain prefix** before signing. It is not a SEP-53 signature. Verify with
  `Keypair.fromPublicKey(publicKey).verify(prefixedBytes, signature)`.
- **Mainnet needs gas.** Fund the app's Stellar gas in the dashboard, or sponsored calls fail.

## Version note

Written for `@cavos/kit` 0.5.2. Verified on Stellar mainnet on 2026-11-12: account
[GCTAQX…P5LG4Q](https://stellar.expert/explorer/public/account/GCTAQXKRGWROJ5UZBLUQ472PNNFOPQQOJBPCVSVCM5SKPKDOAVP5LG4Q),
created by the Cavos relayer, with a sponsored Circle USDC trustline.

## Sources

- https://docs.cavos.xyz/docs/stellar
- https://docs.cavos.xyz/docs/react
- https://docs.cavos.xyz/docs/signing
- https://docs.cavos.xyz/docs/troubleshooting
- https://github.com/cavos-labs/kit
