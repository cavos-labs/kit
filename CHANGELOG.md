# Changelog

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
