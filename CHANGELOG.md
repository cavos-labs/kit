# Changelog

## 0.1.10

- **Keywords & README:** Added `solana` and `stellar` keywords to `package.json`; updated README with three-chain quickstart examples.
- **Stellar WebCrypto control key:** The Ed25519 control key is now non-extractable in WebCrypto environments. XSS cannot call `exportKey` on the control key; signing remains available while the tab is open.
