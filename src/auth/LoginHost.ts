import { loginNonceOf, pkceChallenge } from "./loginBinding";
import { runEnclaveLogin, type EnclaveLoginOptions, type LoginVerifyRequest } from "./enclaveLogin";
import { WebCryptoLoginKey } from "./loginKey";

/** The public half of a started login: the `nonce` for the provider and the PKCE challenge. */
export interface LoginStart {
  nonce: string;
  codeChallenge: string;
}

/**
 * Where a login's key lives and where its enclave jobs run: the Cavos vault
 * (`vaultLoginHost`) or, with the vault off, this page (`createLoginHost`).
 * The caller only ever sees public values and the signed token.
 */
export interface LoginHost {
  /** Make a new login key, replacing the previous one, and return what is public about it. */
  start(): Promise<LoginStart>;
  /**
   * Verify with the enclave, under the key `start` made, and return the id_token it signed.
   * Fails when no login is in progress.
   */
  verify(request: LoginVerifyRequest): Promise<string>;
  /** Delete the login key. */
  end(): Promise<void>;
}

/** A login host over this context's IndexedDB. The vault handler uses the same one. */
export function createLoginHost(opts: EnclaveLoginOptions): LoginHost {
  return {
    async start() {
      const key = await WebCryptoLoginKey.create(opts.appId);
      return { nonce: loginNonceOf(key.publicKeyRaw()), codeChallenge: pkceChallenge(key.codeVerifier) };
    },
    async verify(request) {
      const key = await WebCryptoLoginKey.load(opts.appId);
      if (!key) throw new Error("kit/auth: no sign-in in progress. Sign in again.");
      return runEnclaveLogin(opts, key, request);
    },
    end: () => WebCryptoLoginKey.remove(opts.appId),
  };
}
