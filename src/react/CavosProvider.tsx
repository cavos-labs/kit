'use client';

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useRef,
  type ReactNode,
} from 'react';
import { Cavos } from '../Cavos';
import type { Chain, NetworkEnv, CavosWallet } from '../Cavos';
import { CavosSolana } from '../chains/solana/CavosSolana';
import type { SolanaNetwork } from '../chains/solana/constants';
import { PasskeyPrf } from '../chains/stellar/PasskeyPrf';
import { CavosAuth } from '../auth/CavosAuth';
import type { Identity } from '../auth/AuthProvider';
import type { ChainCall, ExecuteOptions } from '../chains/ChainAdapter';
import { PasskeySigner } from '../signer/PasskeySigner';
import type { PasskeyEnrollParams } from '../signer/PasskeySigner';
import { HttpRecoveryClient } from '../recovery/HttpRecoveryClient';
import { generateRecoveryCode } from '../recovery/BackupSigner';
import { CavosAuthModal } from './CavosAuthModal';
import type { MessageSignature } from '../signing';

export interface CavosConfig {
  /** Cavos App ID from the dashboard. */
  appId?: string;
  /** Target chain. Defaults to 'starknet'. */
  chain?: Chain;
  /** Environment: 'testnet' (sepolia/devnet) or 'mainnet'. */
  network: NetworkEnv;
  /** Per-app salt so the same user has distinct wallets per app. */
  appSalt: string;
  /** Cavos paymaster API key (sponsors deploy + execute). Required for Starknet. */
  paymasterApiKey?: string;
  /** Override the Cavos auth backend (self-hosted / staging). */
  authBackendUrl?: string;
  /** Override the chain RPC. */
  rpcUrl?: string;
}

export interface CavosModalConfig {
  appName?: string;
  appLogo?: string;
  /** Logo height in px. Applies to both a custom `appLogo` (img) and the
   *  default Cavos star. Defaults to 40 (img) / 34 (star). */
  appLogoSize?: number;
  providers?: ('google' | 'apple' | 'email')[];
  /** How the built-in email provider authenticates. Defaults to magic link. */
  emailMode?: 'magic-link' | 'otp';
  primaryColor?: string;
  /** 'light' (default) or 'dark'. */
  theme?: 'light' | 'dark';
  /** Override the modal card background color (defaults to white/#111 per theme). */
  backgroundColor?: string;
  /** Card / button corner radius in px (card defaults to 16, buttons to 8). */
  radius?: number;
  /**
   * Controls the one-time "secure your account" step (passkey / recovery
   * phrase) shown after a brand-new account is created.
   *  - 'optional' (default): show the screen with a "Skip for now" button.
   *  - 'required': show the screen without Skip — the user must set up a
   *    passkey or recovery phrase before finishing onboarding.
   *  - 'off': skip the screen entirely; onboarding ends right after the
   *    account is ready (use this to avoid interrupting your own flow).
   */
  secureStep?: 'optional' | 'required' | 'off';
  onSuccess?: (address: string) => void;
}

/** Minimal wallet-status surface the React layer (and modal) needs. */
export interface WalletStatus {
  /** True while the device-signer account is being deployed. */
  isDeploying: boolean;
  /** True once deployed and this device is an authorized signer. */
  isReady: boolean;
  /** True if this device still needs approval to operate the wallet. */
  needsDeviceApproval: boolean;
  /** True while waiting for the owner to approve this device from another device. */
  awaitingApproval: boolean;
  /** The pending device-addition request id, when awaitingApproval. */
  pendingRequestId: string | null;
  /** True if the account already has a passkey enrolled as an approver, so the
   * modal can offer passkey approval over email on the new-device path. */
  hasPasskey: boolean;
  /** True right after a brand-new account is created (first sign-up), so the UI
   * can offer a one-time "secure your account" step. Cleared once handled. */
  isNewAccount: boolean;
}

export interface UserInfo {
  userId: string;
  email?: string;
  /** Display name from the OAuth id_token (Google only today). May be unset. */
  name?: string;
  provider?: string;
}

export interface CavosContextValue {
  /** Open / close the built-in auth modal. */
  openModal: () => void;
  closeModal: () => void;
  isAuthenticated: boolean;
  user: UserInfo | null;
  /** The active chain ('starknet' | 'solana' | 'stellar'). */
  chain: Chain;
  /**
   * The connected wallet, discriminated by `wallet.chain`. Narrow on
   * `wallet.chain` before chain-native calls (e.g. Solana `wallet.execute(amount,
   * dest)`). Null until connected.
   */
  wallet: CavosWallet | null;
  address: string | null;
  walletStatus: WalletStatus;
  isLoading: boolean;
  /** Last unrecoverable auth/connect error surfaced to the UI (e.g. a failed
   * OAuth callback). Null while things are healthy. Cleared on a new attempt. */
  authError: string | null;
  /** Clear `authError` (e.g. when the user starts a new login attempt). */
  clearAuthError: () => void;
  /** OAuth social login — opens the provider's hosted flow. */
  login: (provider: 'google' | 'apple') => Promise<void>;
  /** Send a passwordless magic-link email. */
  sendMagicLink: (email: string) => Promise<void>;
  /** Send an email OTP code. */
  sendOtp: (email: string) => Promise<void>;
  /** Verify an email OTP / complete a magic link and deploy the wallet. */
  verifyOtp: (email: string, code: string) => Promise<void>;
  /** Resolve identity from an OAuth callback (?auth_data=…) and deploy. */
  handleCallback: (authData: string) => Promise<void>;
  /**
   * Execute a multicall signed by the device key (Starknet-only — on Solana /
   * Stellar call `wallet.execute(...)` directly). Sponsored (gasless) by default;
   * pass `{ sponsored: false }` to submit directly with the account paying its
   * own fee.
   */
  execute: (calls: ChainCall[], opts?: ExecuteOptions) => Promise<{ transactionHash: string }>;
  /**
   * Sign an arbitrary message off-chain with the wallet's signing key. Chain-
   * agnostic (uniform `MessageSignature` return); delegates to
   * `wallet.signMessage` after narrowing on `wallet.chain`. See
   * [After sign-in](https://docs.cavos.xyz/docs/post-login) for per-chain formats
   * and verification.
   */
  signMessage: (message: string | Uint8Array) => Promise<MessageSignature>;
  /** Authorize another device signer on this wallet (sponsored add_signer). */
  addSigner: (pubkey: { x: bigint; y: bigint }) => Promise<{ transactionHash: string }>;
  /** Re-request the device-approval email for the current pending request. */
  resendDeviceApproval: () => Promise<void>;
  /**
   * Enroll a passkey as an approver (2FA-style step-up). Requires a ready device;
   * returns the passkey's public key.
   */
  enrollPasskey: (
    passkey: PasskeySigner,
    params: PasskeyEnrollParams,
  ) => Promise<{ publicKey: { x: bigint; y: bigint }; transactionHash?: string }>;
  /** Whether this device can use a platform passkey (Face ID / Touch ID / PIN). */
  passkeySupported: boolean;
  /**
   * Modal-friendly wrapper: enroll a synced passkey as an approver using the
   * signed-in user's identity + the app name. Requires a ready device.
   */
  enrollPasskeyDefault: () => Promise<void>;
  /**
   * Modal-friendly wrapper for the new-device flow: prompt the user's synced
   * passkey to approve THIS device, then refresh to a ready state. Sponsored by
   * the default paymaster/relayer.
   */
  approveDeviceWithPasskey: () => Promise<void>;
  /**
   * Register a backup signer derived from a generated recovery code (gasless).
   * Resolves with the code so the caller can display it once.
   */
  setupRecovery: () => Promise<string>;
  /**
   * Recover access after losing every device. Requires the recovery code. Brings
   * the provider to a ready state.
   */
  recover: (code: string) => Promise<void>;
  logout: () => void;
}

const CavosContext = createContext<CavosContextValue | null>(null);

export interface CavosProviderProps {
  /** A single chain config. The provider manages exactly one chain. */
  config: CavosConfig;
  modal?: CavosModalConfig;
  children: ReactNode;
}

const INITIAL_STATUS: WalletStatus = {
  isDeploying: false,
  isReady: false,
  needsDeviceApproval: false,
  awaitingApproval: false,
  pendingRequestId: null,
  hasPasskey: false,
  isNewAccount: false,
};

/**
 * Drop-in Cavos provider for ONE chain. Wrap your app once; descendants call
 * `useCavos()`.
 *
 *   <CavosProvider config={{ chain: 'solana', network: 'testnet', appId, appSalt }}
 *                  modal={{ appName: 'My App', theme: 'dark' }}>
 *     <App />
 *   </CavosProvider>
 *
 * Behind the scenes: login (social / email) resolves a stable identity, the kit
 * deploys a device-signer smart account gaslessly, and the wallet handle submits
 * gasless transactions signed silently by the browser's device key.
 */
export function CavosProvider({ config, modal, children }: CavosProviderProps) {
  const [auth] = useState(
    () => new CavosAuth({ appId: config.appId, backendUrl: config.authBackendUrl }),
  );
  const [wallet, setWallet] = useState<CavosWallet | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [walletStatus, setWalletStatus] = useState<WalletStatus>(INITIAL_STATUS);
  // Keep children behind the loading state until we have checked for a
  // persisted identity and silently reconnected this browser's device signer.
  const [isLoading, setIsLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [passkeySupported, setPasskeySupported] = useState(false);
  /** App name/logo fetched from the backend; overrides manual modal props when present. */
  const [branding, setBranding] = useState<{ appName?: string; appLogo?: string }>({});

  // Detect platform-passkey support once, so the modal can hide passkey options
  // on devices/browsers that can't offer them.
  useEffect(() => {
    let cancelled = false;
    PasskeySigner.isSupported()
      .then((ok) => { if (!cancelled) setPasskeySupported(ok); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // Keep the latest config for callbacks that run after async gaps.
  const configRef = useRef(config);
  useEffect(() => {
    configRef.current = config;
  });

  // Fetch app branding (name, logo) from the backend so the modal shows the
  // integrating app's identity without manual props.
  useEffect(() => {
    if (!config.appId || typeof window === 'undefined') return;
    const base = config.authBackendUrl ?? 'https://cavos.xyz';
    fetch(`${base}/api/oauth/firebase/app-branding?app_id=${encodeURIComponent(config.appId)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.name) setBranding((b) => ({ ...b, appName: d.name }));
        if (d?.logo_url) {
          setBranding((b) => ({ ...b, appLogo: d.logo_url }));
          // Warm the browser cache now, while the modal is still closed. The
          // <img> only mounts when the modal opens, so without this the logo
          // downloads cold at open time and visibly pops in after the fallback
          // mark. Preloading here makes it appear instantly on first open.
          const img = new Image();
          img.src = d.logo_url;
        }
      })
      .catch(() => {});
  }, [config.appId, config.authBackendUrl]);

  const openModal = useCallback(() => setModalOpen(true), []);
  const closeModal = useCallback(() => setModalOpen(false), []);
  const clearAuthError = useCallback(() => setAuthError(null), []);

  // Re-request the device-approval email for the current pending request
  // (Starknet-only email flow). The backend dedups within its TTL.
  const resendDeviceApproval = useCallback(async () => {
    const cfg = configRef.current;
    // Email device-approval works on both Starknet and Solana (same secp256r1
    // device key; backend is chain-agnostic). Other chains have no email flow.
    if (!identity || !wallet || (wallet.chain !== 'starknet' && wallet.chain !== 'solana') || !wallet.pendingRequestId) return;
    const backendUrl = cfg.authBackendUrl ?? 'https://cavos.xyz';
    if (!cfg.appId) return;
    const recovery = new HttpRecoveryClient({ baseUrl: backendUrl, appId: cfg.appId });
    await recovery.requestDeviceAddition({
      userId: identity.userId,
      accountAddress: wallet.address,
      newSigner: wallet.publicKey,
      ...(identity.email ? { email: identity.email } : {}),
    });
  }, [identity, wallet]);

  // Connect the configured chain for an identity (deploys if needed), then
  // publish its status. `silent` reconnects keep the current screen instead of
  // resetting to the deploying state (used right after a passkey approval).
  const connect = useCallback(async (id: Identity, opts?: { silent?: boolean }): Promise<CavosWallet> => {
    const cfg = configRef.current;
    if (!opts?.silent) setWalletStatus({ ...INITIAL_STATUS, isDeploying: true });
    const w = await Cavos.connect({
      chain: cfg.chain ?? 'starknet',
      network: cfg.network,
      identity: id,
      appSalt: cfg.appSalt,
      ...(cfg.paymasterApiKey ? { paymasterApiKey: cfg.paymasterApiKey } : {}),
      ...(cfg.appId ? { appId: cfg.appId } : {}),
      ...(cfg.authBackendUrl ? { backendUrl: cfg.authBackendUrl } : {}),
      ...(cfg.rpcUrl ? { rpcUrl: cfg.rpcUrl } : {}),
    });
    setWallet(w);
    setIdentity(id);

    // Starknet and Solana both support the email device-approval flow (both carry
    // a pendingRequestId when a returning-new-device request was filed). Stellar
    // has its own passkey-PRF device model with no email flow today.
    const pendingRequestId = w.chain === 'starknet' || w.chain === 'solana' ? w.pendingRequestId : null;
    let hasPasskey = false;
    if (w.status === 'needs-device-approval') {
      try { hasPasskey = await w.hasPasskey(); } catch { /* leave false → email flow */ }
    }

    setWalletStatus({
      isDeploying: false,
      isReady: w.status === 'ready',
      needsDeviceApproval: w.status === 'needs-device-approval',
      awaitingApproval: w.status === 'needs-device-approval' && !!pendingRequestId,
      pendingRequestId,
      hasPasskey,
      isNewAccount: w.isNewAccount,
    });
    modal?.onSuccess?.(w.address);
    return w;
  }, [modal]);

  // On mount: if we're returning from OAuth (?auth_data=…), finish the login.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const authData = params.get('auth_data') || params.get('zk_auth_data');
    if (!authData) return;
    setModalOpen(true);
    setWalletStatus({ ...INITIAL_STATUS, isDeploying: true });
    let cancelled = false;
    (async () => {
      setIsLoading(true);
      try {
        await handleCallback(authData);
        if (!cancelled) window.history.replaceState({}, document.title, window.location.pathname);
      } catch (e) {
        console.error('[CavosProvider] OAuth callback error:', e);
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : 'Sign-in failed. Please try again.';
          setAuthError(msg);
          setWalletStatus(INITIAL_STATUS);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCallback = useCallback(async (authData: string) => {
    const id = await auth.handleCallback(authData);
    await connect(id);
  }, [auth, connect]);

  // A device signer is already persisted securely in IndexedDB. Restore only
  // the non-secret identity metadata from localStorage, then reconnect the
  // existing signer without another OAuth prompt.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("auth_data") || params.get("zk_auth_data")) return;

    const savedIdentity = auth.restoreIdentity();
    if (!savedIdentity) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        await connect(savedIdentity);
      } catch (e) {
        // Keep the identity so a transient RPC failure does not force OAuth on
        // the next launch. The app can surface the normal sign-in UI if needed.
        console.warn("[CavosProvider] silent reconnect failed:", e);
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [auth, connect]);

  const login = useCallback(async (provider: 'google' | 'apple') => {
    if (typeof window === 'undefined') throw new Error('OAuth requires a browser');
    setAuthError(null);
    const url = await (provider === 'google'
      ? auth.getGoogleOAuthUrl(window.location.origin + window.location.pathname)
      : auth.getAppleOAuthUrl(window.location.origin + window.location.pathname));
    window.location.href = url;
  }, [auth]);

  const sendMagicLink = useCallback(async (email: string) => {
    await auth.sendMagicLink(email);
  }, [auth]);

  const sendOtp = useCallback(async (email: string) => {
    await auth.sendOtp(email);
  }, [auth]);

  const verifyOtp = useCallback(async (email: string, code: string) => {
    setAuthError(null);
    const id = await auth.verifyOtp(email, code);
    await connect(id);
  }, [auth, connect]);

  const execute = useCallback(async (calls: ChainCall[], opts?: ExecuteOptions) => {
    if (!wallet) throw new Error('Not logged in');
    if (wallet.chain !== 'starknet') {
      throw new Error(
        "kit: useCavos().execute(calls) is Starknet-only. On Solana/Stellar use the `wallet` handle: wallet.execute(amount, dest).",
      );
    }
    return wallet.execute(calls, opts);
  }, [wallet]);

  // Chain-agnostic off-chain message signing. Every chain's wallet exposes the
  // same `signMessage(message)` signature returning a uniform `MessageSignature`.
  const signMessage = useCallback(
    async (message: string | Uint8Array): Promise<MessageSignature> => {
      if (!wallet) throw new Error('Not logged in');
      return wallet.signMessage(message);
    },
    [wallet],
  );

  const addSigner = useCallback(
    async (pubkey: { x: bigint; y: bigint }) => {
      if (!wallet) throw new Error('Not logged in');
      if (wallet.chain !== 'starknet') {
        throw new Error('kit: addSigner via useCavos() is Starknet-only; use the `wallet` handle on other chains.');
      }
      return wallet.addSigner(pubkey);
    },
    [wallet],
  );

  const enrollPasskey = useCallback(
    async (passkey: PasskeySigner, params: PasskeyEnrollParams) => {
      if (!wallet) throw new Error('Not logged in');
      if (wallet.chain === 'stellar') {
        throw new Error(
          'kit: on Stellar, use enrollPasskeyDefault() — the passkey factor is a WebAuthn PRF secret, not a signer object.',
        );
      }
      return wallet.enrollPasskey(passkey, params);
    },
    [wallet],
  );

  const rpName = branding.appName ?? modal?.appName ?? 'Cavos';

  // Enroll a synced passkey as an approver on the connected chain (single OS prompt).
  const enrollPasskeyDefault = useCallback(async () => {
    if (!wallet || !identity) throw new Error('Not logged in');
    if (wallet.status !== 'ready') throw new Error('kit: no ready device to enroll a passkey on');
    if (wallet.chain === 'stellar') {
      // Classic Stellar uses a WebAuthn PRF secret (not an on-chain assertion) as
      // the passkey factor that wraps the account DEK.
      const prf = new PasskeyPrf({ rpName });
      const { secret } = await prf.enroll({
        userId: identity.userId,
        userName: identity.email ?? identity.userId,
        ...(identity.email ? { displayName: identity.email } : {}),
      });
      await wallet.enrollPasskey(secret ?? (await prf.getSecret()));
      return;
    }
    const passkey = new PasskeySigner({ rpName });
    await wallet.enrollPasskey(passkey, {
      userId: identity.userId,
      userName: identity.email ?? identity.userId,
      ...(identity.email ? { displayName: identity.email } : {}),
    });
  }, [wallet, identity, rpName]);

  // New-device flow: ONE passkey prompt approves THIS device on the connected
  // chain, then poll readiness and reconnect once.
  const approveDeviceWithPasskey = useCallback(async () => {
    if (!wallet || !identity) throw new Error('Not logged in');
    if (wallet.status !== 'needs-device-approval') {
      await connect(identity);
      return;
    }
    if (wallet.chain === 'stellar') {
      const prf = new PasskeyPrf({ rpName });
      await wallet.approveThisDeviceWithPasskey(await prf.getSecret());
    } else if (wallet.chain === 'starknet') {
      const passkey = new PasskeySigner({ rpName });
      await wallet.approveThisDeviceWithPasskey({ passkey });
    } else {
      const passkey = new PasskeySigner({ rpName });
      await wallet.approveThisDeviceWithPasskey(passkey);
    }
    // The on-chain add_signer isn't indexed the instant the tx submits — show the
    // deploying state and poll readiness (cheap, side-effect free) until it lands.
    setWalletStatus((s) => ({ ...s, isDeploying: true, needsDeviceApproval: false, awaitingApproval: false }));
    const deadline = Date.now() + 60_000;
    for (;;) {
      let ready = false;
      try { ready = await wallet.isReady(); } catch { /* transient RPC — retry */ }
      if (ready) break;
      if (Date.now() > deadline) {
        setWalletStatus((s) => ({ ...s, isDeploying: false, needsDeviceApproval: true }));
        throw new Error(
          "Your device is being added, but it's taking longer than usual. Please try again in a moment.",
        );
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
    await connect(identity, { silent: true });
  }, [wallet, identity, rpName, connect]);

  // Generate a recovery code and register its derived backup signer (gasless).
  // The code is returned so the UI can display it once — never persisted.
  const setupRecovery = useCallback(async (): Promise<string> => {
    if (!wallet) throw new Error('Not logged in');
    const code = generateRecoveryCode();
    await wallet.setupRecovery(code);
    return code;
  }, [wallet]);

  // Recover access after losing every device on the configured chain.
  const recover = useCallback(async (code: string) => {
    if (!identity) throw new Error('Sign in first so we know which account to recover.');
    const cfg = configRef.current;
    setAuthError(null);
    setWalletStatus({ ...INITIAL_STATUS, isDeploying: true });
    try {
      const chain = cfg.chain ?? 'starknet';
      let w: CavosWallet;
      if (chain === 'solana') {
        w = await CavosSolana.recover({
          code,
          identity,
          network: (cfg.network === 'mainnet' ? 'solana-mainnet' : 'solana-devnet') as SolanaNetwork,
          appSalt: cfg.appSalt,
          ...(cfg.appId ? { appId: cfg.appId } : {}),
          ...(cfg.authBackendUrl ? { backendUrl: cfg.authBackendUrl } : {}),
          ...(cfg.rpcUrl ? { rpcUrl: cfg.rpcUrl } : {}),
        });
      } else if (chain === 'stellar') {
        // Classic `G…`: reconnect this (fresh) device, then use the recovery code
        // to approve it — the code unlocks the control key which authorizes adding
        // this device's slot. The account already exists, so no funder is needed.
        const sw = await Cavos.connect({
          chain: 'stellar',
          network: cfg.network,
          identity,
          appSalt: cfg.appSalt,
          ...(cfg.appId ? { appId: cfg.appId } : {}),
          ...(cfg.authBackendUrl ? { backendUrl: cfg.authBackendUrl } : {}),
        });
        if (sw.chain === 'stellar' && sw.status === 'needs-device-approval') {
          await sw.approveThisDeviceWithRecovery(code);
        }
        w = sw;
      } else {
        w = await Cavos.recover({
          code,
          identity,
          network: cfg.network,
          appSalt: cfg.appSalt,
          paymasterApiKey: cfg.paymasterApiKey ?? '',
          ...(cfg.appId ? { appId: cfg.appId } : {}),
          ...(cfg.authBackendUrl ? { backendUrl: cfg.authBackendUrl } : {}),
          ...(cfg.rpcUrl ? { rpcUrl: cfg.rpcUrl } : {}),
        });
      }
      setWallet(w);
      setWalletStatus({ ...INITIAL_STATUS, isReady: true });
      modal?.onSuccess?.(w.address);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Recovery failed. Check your code and try again.';
      setAuthError(msg);
      setWalletStatus(INITIAL_STATUS);
      throw e;
    }
  }, [identity, modal]);

  // Poll the pending device-addition request while awaiting the owner's approval
  // (Starknet email flow). Once approved, reconnect to flip to "ready".
  useEffect(() => {
    if (!walletStatus.awaitingApproval || !walletStatus.pendingRequestId || !identity) return;
    const cfg = configRef.current;
    if (!cfg.appId) return;
    const backendUrl = cfg.authBackendUrl ?? 'https://cavos.xyz';
    const recovery = new HttpRecoveryClient({ baseUrl: backendUrl, appId: cfg.appId });
    const requestId = walletStatus.pendingRequestId;
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await recovery.getPendingRequest(requestId);
        if (cancelled || !r) return;
        if (r.status === 'expired') {
          setWalletStatus((s) => ({ ...s, pendingRequestId: null }));
          return;
        }
        if (r.status === 'approved') {
          await connect(identity);
        }
      } catch {
        /* transient network errors are fine; the next tick retries */
      }
    };
    const interval = setInterval(tick, 4000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [walletStatus.awaitingApproval, walletStatus.pendingRequestId, identity, connect]);

  const logout = useCallback(() => {
    auth.clearStoredIdentity();
    setWallet(null);
    setIdentity(null);
    setWalletStatus(INITIAL_STATUS);
    setAuthError(null);
  }, [auth]);

  const value: CavosContextValue = {
    openModal,
    closeModal,
    isAuthenticated: !!wallet,
    user: identity
      ? { userId: identity.userId, email: identity.email, name: identity.name, provider: identity.provider }
      : null,
    chain: config.chain ?? 'starknet',
    wallet,
    address: wallet?.address ?? null,
    walletStatus,
    isLoading,
    authError,
    clearAuthError,
    login,
    sendMagicLink,
    sendOtp,
    verifyOtp,
    handleCallback,
    execute,
    signMessage,
    addSigner,
    enrollPasskey,
    passkeySupported,
    enrollPasskeyDefault,
    approveDeviceWithPasskey,
    resendDeviceApproval,
    setupRecovery,
    recover,
    logout,
  };

  return (
    <CavosContext.Provider value={value}>
      {children}
      {modal !== undefined && (
        <CavosAuthModal
          open={modalOpen}
          onClose={closeModal}
          appName={branding.appName ?? modal.appName}
          appLogo={branding.appLogo ?? modal.appLogo}
          appLogoSize={modal.appLogoSize}
          providers={modal.providers}
          emailMode={modal.emailMode}
          primaryColor={modal.primaryColor}
          theme={modal.theme}
          backgroundColor={modal.backgroundColor}
          radius={modal.radius}
          secureStep={modal.secureStep}
        />
      )}
    </CavosContext.Provider>
  );
}

export function useCavos(): CavosContextValue {
  const ctx = useContext(CavosContext);
  if (!ctx) throw new Error('useCavos must be used within a CavosProvider');
  return ctx;
}
