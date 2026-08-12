'use client';

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useMemo,
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
import type { PasskeyApprover, PasskeyEnrollParams } from '../signer/PasskeyProvider';
import { HttpRecoveryClient } from '../recovery/HttpRecoveryClient';
import { generateRecoveryCode } from '../recovery/BackupSigner';
import {
  SocialRecoveryClient,
  type AttestationPolicy,
  type SocialRecoveryPrewarm,
  type SocialRecoveryProvider,
} from '../recovery/SocialRecoveryClient';
import {
  enrollHardwareIsolatedRecovery,
  recoverHardwareIsolatedDevice,
} from '../recovery/SocialRecoveryCoordinator';
import type { SocialRecoveryCredential } from '../recovery/SocialRecoveryCredential';
import {
  DEFAULT_SOCIAL_RECOVERY_ATTESTATION,
  DEFAULT_SOCIAL_RECOVERY_STARKNET_CLASS_HASH,
} from '../recovery/attestationDefaults';
import { CavosAuthModal } from './CavosAuthModal';
import {
  validateCavosConfig,
  checkAppSaltDrift,
  formatConfigProblems,
} from './validateConfig';
import type { MessageSignature } from '../signing';

export interface CavosConfig {
  /** Cavos App ID from the dashboard. */
  appId?: string;
  /** Cavos console environment. Defaults to production when omitted. */
  environment?: 'development' | 'production';
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
  /** Explicit OAuth callback. Optional on web; required by the native provider. */
  redirectUri?: string;
  /** Passkey relying-party id. Optional on web; required by the native provider. */
  rpId?: string;
  /** Native-only key policy; retained here so config objects remain portable. */
  minimumKeySecurity?: 'os-protected' | 'hardware';
  /**
   * Turn on hardware-isolated social recovery using the enclave Cavos operates,
   * pinned by the constants shipped in this package. The feature must also be
   * enabled for the app's environment in the dashboard.
   *
   * Pass an `AttestationPolicy` instead to pin your own measurements — required
   * if you run your own enclave. Values pinned here are never learned from the
   * control plane whose enclave is being verified.
   */
  socialRecovery?: boolean | AttestationPolicy;
  /**
   * @deprecated Use `socialRecovery`. Passing a policy here still works and
   * takes precedence, so existing apps keep their explicit pin.
   */
  socialRecoveryAttestation?: AttestationPolicy;
  /**
   * Declared DeviceAccount class containing social-recovery entrypoints, used
   * to upgrade Starknet accounts deployed before the feature; their address and
   * signer storage stay unchanged. Defaults to the class Cavos declared.
   */
  socialRecoveryStarknetClassHash?: string;
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
  /** The attested enclave is enrolling or recovering this wallet. */
  isSocialRecovering: boolean;
  /** Unix seconds when an on-chain timelocked recovery can be finalized. */
  socialRecoveryReadyAt: number | null;
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
    passkey: PasskeyApprover,
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
  /**
   * Drive social recovery with a provider id_token your own login already
   * obtained, so the user never signs in twice.
   *
   * Enrols when this device is ready and recovers when it is not — the wallet's
   * state decides. Pass the raw Google or Apple `id_token`, not your own session
   * JWT, and pass it straight from a sign-in: the enclave requires the
   * authentication to be under five minutes old.
   *
   * Requires the app's own OAuth client ID to be registered for the environment
   * in the dashboard, so the enclave accepts tokens minted for your client.
   * Progress shows up on `walletStatus.isSocialRecovering`.
   */
  submitSocialRecoveryToken: (idToken: string) => void;
  logout: () => void;
}

const CavosContext = createContext<CavosContextValue | null>(null);

export interface CavosProviderProps {
  /** A single chain config. The provider manages exactly one chain. */
  config: CavosConfig;
  modal?: CavosModalConfig;
  /**
   * Bring your own auth: the signed-in user from Clerk, Auth0, your own
   * backend, anything. When set, the provider skips its own login entirely —
   * the modal never opens and `login()` throws — and connects this user's
   * wallet directly.
   *
   * Pass `null` while your auth is still loading or once the user signs out;
   * the provider clears its state in step with you.
   *
   * This identity is deliberately **not persisted**. Your auth stays the single
   * source of truth on every mount, so a Cavos session can never outlive the
   * session that authorized it.
   *
   * `userId` must be stable and unique per user — the wallet address derives
   * from it. Use an immutable primary key, never an email or username.
   */
  identity?: Identity | null;
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
  isSocialRecovering: false,
  socialRecoveryReadyAt: null,
};

interface SocialRecoveryEnvironment {
  enabled: boolean;
  provider: SocialRecoveryProvider | null;
  delaySeconds: number;
}

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
/**
 * Resolve the attestation policy this app verifies the enclave against.
 *
 * An explicit policy always wins, so an app that pinned its own measurements
 * keeps them. `socialRecovery: true` opts into the enclave Cavos operates,
 * pinned by the constants shipped in this package — never fetched from the
 * control plane whose enclave is being verified.
 */
export function resolveSocialRecoveryPolicy(
  config: Pick<CavosConfig, 'socialRecovery' | 'socialRecoveryAttestation'>,
): AttestationPolicy | undefined {
  if (config.socialRecoveryAttestation) return config.socialRecoveryAttestation;
  if (typeof config.socialRecovery === 'object') return config.socialRecovery;
  if (config.socialRecovery === true) return DEFAULT_SOCIAL_RECOVERY_ATTESTATION;
  return undefined;
}

export function CavosProvider({
  config,
  modal,
  identity: externalIdentity,
  children,
}: CavosProviderProps) {
  // `undefined` = the host is not supplying identity (Cavos runs its own auth).
  // `null` = the host supplies identity and nobody is signed in yet.
  const isExternalAuth = externalIdentity !== undefined;
  // Surface configuration mistakes at mount, where they are cheap to fix,
  // instead of as an indirect failure several steps into a user's first login.
  // Development only: these are for whoever is integrating, not end users.
  useEffect(() => {
    if (process.env.NODE_ENV === 'production') return;
    const problems = validateCavosConfig(config);
    const drift = checkAppSaltDrift(config);
    if (drift) problems.unshift(drift);
    if (problems.length === 0) return;
    const log = problems.some((p) => p.level === 'error') ? console.error : console.warn;
    log(`[CavosProvider] configuration:\n${formatConfigProblems(problems)}`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Bumped when the host hands us a provider token, so the enrol/recover
  // effect below re-runs — the credential lives on `auth`, not in React state.
  const [externalSocialToken, setExternalSocialToken] = useState(0);

  const socialRecoveryPolicy = useMemo(
    () => resolveSocialRecoveryPolicy(config),
    [config.socialRecovery, config.socialRecoveryAttestation],
  );
  const socialRecoveryStarknetClassHash =
    config.socialRecoveryStarknetClassHash ??
    DEFAULT_SOCIAL_RECOVERY_STARKNET_CLASS_HASH;
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
  const [socialRecovery, setSocialRecovery] =
    useState<SocialRecoveryEnvironment | null>(null);
  const socialAttemptRef = useRef(new Set<string>());
  const socialPrewarmRef = useRef<SocialRecoveryPrewarm | null>(null);
  const socialPrewarmPromiseRef = useRef<Promise<SocialRecoveryPrewarm | null> | null>(null);
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

  // The dashboard chooses exactly one provider per environment. This public
  // policy controls login UX only; enclave measurements remain developer-pinned
  // in `config.socialRecoveryAttestation`.
  useEffect(() => {
    if (!config.appId || typeof window === 'undefined') return;
    const base = config.authBackendUrl ?? 'https://cavos.xyz';
    const query = new URLSearchParams({
      app_id: config.appId,
      ...(config.environment ? { environment: config.environment } : {}),
    });
    fetch(`${base}/api/recovery/social/config?${query}`)
      .then(async (response) => {
        if (!response.ok) throw new Error(`social recovery config ${response.status}`);
        return response.json();
      })
      .then((data) => {
        setSocialRecovery({
          enabled: data.enabled === true,
          provider: ['google', 'apple', 'email'].includes(data.provider)
            ? data.provider
            : null,
          delaySeconds: Number(data.delay_seconds) || 0,
        });
      })
      .catch(() => setSocialRecovery({ enabled: false, provider: null, delaySeconds: 0 }));
  }, [config.appId, config.environment, config.authBackendUrl]);

  const openModal = useCallback(() => {
    // Under external auth there is nothing for the modal to do: showing a
    // second sign-in surface next to the host's own is a bug, not a feature.
    if (isExternalAuth) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn(
          '[CavosProvider] openModal() ignored: this provider uses your `identity` prop, not Cavos login.',
        );
      }
      return;
    }
    setModalOpen(true);
  }, [isExternalAuth]);
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
    const recovery = new HttpRecoveryClient({ baseUrl: backendUrl, appId: cfg.appId, environment: cfg.environment });
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
      ...(cfg.environment ? { environment: cfg.environment } : {}),
      ...(cfg.authBackendUrl ? { backendUrl: cfg.authBackendUrl } : {}),
      ...(cfg.rpcUrl ? { rpcUrl: cfg.rpcUrl } : {}),
      ...(resolveSocialRecoveryPolicy(cfg)
        ? { legacyDeviceApproval: false }
        : {}),
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
      isSocialRecovering: false,
      socialRecoveryReadyAt: null,
    });
    modal?.onSuccess?.(w.address);
    return w;
  }, [modal]);

  const ensureSocialRecoveryPrewarm = useCallback(async (): Promise<SocialRecoveryPrewarm | null> => {
    const cfg = configRef.current;
    if (!cfg.appId || !resolveSocialRecoveryPolicy(cfg) || typeof window === "undefined") {
      return null;
    }
    const existing =
      socialPrewarmRef.current ?? loadSocialRecoveryPrewarm(cfg.appId, cfg.environment);
    if (existing) {
      socialPrewarmRef.current = existing;
      return existing;
    }
    if (socialPrewarmPromiseRef.current) return socialPrewarmPromiseRef.current;

    const client = new SocialRecoveryClient({
      baseUrl: cfg.authBackendUrl ?? 'https://cavos.xyz',
      appId: cfg.appId,
      environment: cfg.environment,
      attestation: resolveSocialRecoveryPolicy(cfg)!,
    });
    const promise = client
      .prewarm()
      .then((prewarm) => {
        socialPrewarmRef.current = prewarm;
        persistSocialRecoveryPrewarm(cfg.appId!, cfg.environment, prewarm);
        return prewarm;
      })
      .catch((error) => {
        // Prewarming is an optimization only. Login and the normal cold-start
        // recovery path must remain available if capacity or rate limits reject it.
        console.warn('[CavosProvider] social recovery prewarm skipped:', error);
        return null;
      })
      .finally(() => {
        socialPrewarmPromiseRef.current = null;
      });
    socialPrewarmPromiseRef.current = promise;
    return promise;
  }, []);

  const handleCallback = useCallback(async (authData: string, redirectUri?: string) => {
    // On redirect callbacks, continue/recreate the prewarm concurrently with
    // provider-token verification and deterministic wallet discovery.
    const [id] = await Promise.all([
      auth.handleCallback(authData, redirectUri),
      ensureSocialRecoveryPrewarm(),
    ]);
    await connect(id);
  }, [auth, connect, ensureSocialRecoveryPrewarm]);

  // On mount: exchange the one-time OAuth code after removing it from the
  // address bar immediately. Legacy auth_data is accepted only for callbacks
  // already in flight during rollout.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const authData = params.get('cavos_auth_code') || params.get('auth_data') || params.get('zk_auth_data');
    if (!authData) return;
    const cleanUrl = new URL(window.location.href);
    cleanUrl.searchParams.delete('cavos_auth_code');
    cleanUrl.searchParams.delete('auth_data');
    cleanUrl.searchParams.delete('zk_auth_data');
    window.history.replaceState({}, document.title, cleanUrl.pathname + cleanUrl.search + cleanUrl.hash);
    setModalOpen(true);
    setWalletStatus({ ...INITIAL_STATUS, isDeploying: true });
    let cancelled = false;
    (async () => {
      setIsLoading(true);
      try {
        await handleCallback(authData, cleanUrl.toString());
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

  /**
   * A fresh provider credential is available only immediately after login. Use
   * that window to enrol a ready wallet or recover this exact new device. The
   * credential is encrypted to the independently-attested enclave by the SDK.
   */
  useEffect(() => {
    if (
      !socialRecovery?.enabled ||
      !socialRecovery.provider ||
      !wallet ||
      !identity ||
      !config.appId
    ) return;

    let credential: SocialRecoveryCredential;
    try {
      credential = auth.consumeSocialRecoveryCredential();
    } catch {
      return;
    }
    const action = wallet.status === 'ready' ? 'enroll' : 'recover';
    const attemptKey =
      `${wallet.chain}:${wallet.address}:${action}:${credential.tokenFingerprint}`;
    if (socialAttemptRef.current.has(attemptKey)) return;
    socialAttemptRef.current.add(attemptKey);

    if (!socialRecoveryPolicy) {
      if (action === 'recover') {
        setAuthError(
          'Social recovery is enabled for this environment, but the app has not turned it on. ' +
            'Set `socialRecovery: true` in the Cavos config, or pass your own AttestationPolicy.',
        );
      }
      return;
    }

    const prewarm =
      socialPrewarmRef.current ??
      takeSocialRecoveryPrewarm(config.appId, config.environment);
    socialPrewarmRef.current = null;
    clearSocialRecoveryPrewarm(config.appId, config.environment);
    const client = new SocialRecoveryClient({
      baseUrl: config.authBackendUrl ?? 'https://cavos.xyz',
      appId: config.appId,
      environment: config.environment,
      attestation: socialRecoveryPolicy,
      ...(prewarm ? { prewarm } : {}),
    });
    let cancelled = false;

    (async () => {
      if (action === 'enroll') {
        // A newly-created wallet is already controlled by this device. TEE
        // enrollment is a hardening step and must not downgrade the usable
        // wallet back to a blocking "deploying" state while an on-demand
        // Confidential Space VM boots. Browsers may suspend timers in the
        // background; the in-flight task resumes when the app is foregrounded.
        setWalletStatus((status) => ({
          ...status,
          isDeploying: false,
          isReady: true,
          isSocialRecovering: true,
        }));
        try {
          await enrollHardwareIsolatedRecovery({
            client,
            wallet,
            credential,
            delaySeconds: socialRecovery.delaySeconds,
            ...(socialRecoveryStarknetClassHash
              ? { starknetClassHash: socialRecoveryStarknetClassHash }
              : {}),
          });
        } catch (error) {
          // Enrollment is opt-in and must never make an already-working wallet
          // unusable. A 409 means this wallet was enrolled on a prior login.
          const message = error instanceof Error ? error.message : String(error);
          if (!message.includes('already_enrolled')) {
            console.error('[CavosProvider] social recovery enrollment failed:', error);
          }
        } finally {
          if (!cancelled) {
            setWalletStatus((status) => ({
              ...status,
              isDeploying: false,
              isReady: true,
              isSocialRecovering: false,
            }));
          }
        }
        return;
      }

      setWalletStatus((status) => ({
        ...status,
        isDeploying: true,
        needsDeviceApproval: false,
        awaitingApproval: false,
        isSocialRecovering: true,
      }));
      try {
        // A second device can arrive while the first device's automatic TEE
        // enrollment is still finishing. Treat that short race as a pending
        // state instead of immediately surfacing the backend's `not_enrolled`
        // response. The same fresh credential is safe to retry because the
        // control plane does not reserve its fingerprint until an enrollment
        // actually exists and a recovery session is created.
        const enrollmentDeadline = Date.now() + 5 * 60_000;
        let outcome: Awaited<ReturnType<typeof recoverHardwareIsolatedDevice>>;
        for (;;) {
          try {
            outcome = await recoverHardwareIsolatedDevice({
              client,
              wallet,
              credential,
              network: config.network,
              delaySeconds: socialRecovery.delaySeconds,
            });
            break;
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            const enrollmentIsPending =
              message.includes('not_enrolled') ||
              message.includes('social recovery is not enrolled');
            if (
              !enrollmentIsPending ||
              Date.now() >= enrollmentDeadline ||
              cancelled
            ) {
              throw error;
            }
            await new Promise((resolve) => setTimeout(resolve, 5_000));
          }
        }
        if (cancelled) return;
        if (!outcome.finalized) {
          persistPendingSocialRecovery(wallet.chain, wallet.address, outcome.readyAt);
          setWalletStatus((status) => ({
            ...status,
            isDeploying: false,
            needsDeviceApproval: true,
            isSocialRecovering: false,
            socialRecoveryReadyAt: outcome.readyAt,
          }));
          return;
        }
        await waitUntilWalletReady(wallet);
        if (!cancelled) await connect(identity, { silent: true });
      } catch (error) {
        if (!cancelled) {
          setAuthError(error instanceof Error ? error.message : 'Social recovery failed.');
          setWalletStatus((status) => ({
            ...status,
            isDeploying: false,
            needsDeviceApproval: true,
            isSocialRecovering: false,
          }));
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    auth,
    config.appId,
    config.authBackendUrl,
    config.environment,
    config.network,
    socialRecoveryPolicy,
    socialRecoveryStarknetClassHash,
    connect,
    identity,
    socialRecovery,
    wallet,
    externalSocialToken,
  ]);

  // A non-zero timelock survives refreshes: scheduling is already committed
  // on-chain and finalization needs no social credential. Resume it when due.
  useEffect(() => {
    if (!wallet || !identity || wallet.status !== 'needs-device-approval') return;
    const persisted = loadPendingSocialRecovery(wallet.chain, wallet.address);
    const readyAt = walletStatus.socialRecoveryReadyAt ?? persisted;
    if (!readyAt) return;
    if (walletStatus.socialRecoveryReadyAt !== readyAt) {
      setWalletStatus((status) => ({ ...status, socialRecoveryReadyAt: readyAt }));
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const finalize = async () => {
      const remaining = readyAt * 1000 - Date.now();
      if (remaining > 0) {
        timer = setTimeout(finalize, Math.min(remaining, 60_000));
        return;
      }
      setWalletStatus((status) => ({
        ...status,
        isDeploying: true,
        needsDeviceApproval: false,
        isSocialRecovering: true,
      }));
      try {
        if (wallet.chain === 'starknet') await wallet.finalizeSocialRecovery();
        else if (wallet.chain === 'solana') await wallet.finalizeSocialRecovery();
        else return;
        await waitUntilWalletReady(wallet);
        clearPendingSocialRecovery(wallet.chain, wallet.address);
        if (!cancelled) await connect(identity, { silent: true });
      } catch (error) {
        if (!cancelled) {
          setAuthError(error instanceof Error ? error.message : 'Could not finalize recovery.');
          setWalletStatus((status) => ({
            ...status,
            isDeploying: false,
            needsDeviceApproval: true,
            isSocialRecovering: false,
          }));
          timer = setTimeout(finalize, 10_000);
        }
      }
    };
    void finalize();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [connect, identity, wallet, walletStatus.socialRecoveryReadyAt]);

  // A device signer is already persisted securely in IndexedDB. Restore only
  // the non-secret identity metadata from localStorage, then reconnect the
  // existing signer without another OAuth prompt.
  useEffect(() => {
    if (typeof window === "undefined") return;
    // Under external auth the host's identity is the only source of truth, and
    // it is never written to storage. Restoring here would resurrect a session
    // the host may have already ended.
    if (isExternalAuth) return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("cavos_auth_code") || params.get("auth_data") || params.get("zk_auth_data")) return;

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
  }, [auth, connect, isExternalAuth]);

  // Track the host's identity. Connect when it appears, tear down when it
  // clears, and swap cleanly when it changes to a different user.
  const externalUserId = externalIdentity?.userId ?? null;
  useEffect(() => {
    if (!isExternalAuth) return;
    let cancelled = false;

    if (!externalIdentity) {
      // Signed out (or still loading). Drop wallet state so a previous user's
      // address can never be read by whoever comes next.
      setWallet(null);
      setIdentity(null);
      setWalletStatus(INITIAL_STATUS);
      setAuthError(null);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    // Clear the outgoing user's wallet before connecting the incoming one, so
    // a slow connect cannot briefly expose the wrong account.
    setWallet(null);
    setWalletStatus(INITIAL_STATUS);
    (async () => {
      try {
        await connect(externalIdentity, { silent: true });
      } catch (e) {
        if (!cancelled) {
          setAuthError(e instanceof Error ? e.message : 'Could not connect the wallet.');
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // Keyed on the user, not the object: hosts commonly pass a fresh object
    // each render, which would otherwise reconnect on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isExternalAuth, externalUserId, connect]);

  const login = useCallback(async (provider: 'google' | 'apple') => {
    if (isExternalAuth) {
      throw new Error(
        'kit/react: this provider is driven by your own auth (the `identity` prop), so Cavos login is disabled. ' +
          'Sign the user in with your auth and pass the resulting identity.',
      );
    }
    if (typeof window === 'undefined') throw new Error('OAuth requires a browser');
    setAuthError(null);
    await ensureSocialRecoveryPrewarm();
    const url = await (provider === 'google'
      ? auth.getGoogleOAuthUrl(window.location.origin + window.location.pathname)
      : auth.getAppleOAuthUrl(window.location.origin + window.location.pathname));
    window.location.href = url;
  }, [auth, ensureSocialRecoveryPrewarm]);

  const sendMagicLink = useCallback(async (email: string) => {
    await Promise.all([auth.sendMagicLink(email), ensureSocialRecoveryPrewarm()]);
  }, [auth, ensureSocialRecoveryPrewarm]);

  const sendOtp = useCallback(async (email: string) => {
    await Promise.all([auth.sendOtp(email), ensureSocialRecoveryPrewarm()]);
  }, [auth, ensureSocialRecoveryPrewarm]);

  const verifyOtp = useCallback(async (email: string, code: string) => {
    setAuthError(null);
    const [id] = await Promise.all([
      auth.verifyOtp(email, code),
      ensureSocialRecoveryPrewarm(),
    ]);
    await connect(id);
  }, [auth, connect, ensureSocialRecoveryPrewarm]);

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
    async (passkey: PasskeyApprover, params: PasskeyEnrollParams) => {
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
    const recovery = new HttpRecoveryClient({ baseUrl: backendUrl, appId: cfg.appId, environment: cfg.environment });
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

  const submitSocialRecoveryToken = useCallback((idToken: string) => {
    // Throws for a token no provider the enclave trusts could have issued, so
    // the mistake surfaces here instead of as an opaque enclave rejection.
    auth.useExternalSocialRecoveryToken(idToken);
    setExternalSocialToken((n) => n + 1);
  }, [auth]);

  const logout = useCallback(() => {
    auth.clearStoredIdentity();
    setWallet(null);
    setIdentity(null);
    setWalletStatus(INITIAL_STATUS);
    setAuthError(null);
    // Under external auth this only clears Cavos state; the user is still
    // signed in to the host until the host signs them out and clears the prop.
    if (isExternalAuth && process.env.NODE_ENV !== 'production') {
      console.warn(
        '[CavosProvider] logout() cleared Cavos state only. Sign the user out with your own auth and pass `identity={null}`.',
      );
    }
  }, [auth, isExternalAuth]);

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
    submitSocialRecoveryToken,
    logout,
  };

  return (
    <CavosContext.Provider value={value}>
      {children}
      {modal !== undefined && !isExternalAuth && (
        <CavosAuthModal
          open={modalOpen}
          onClose={closeModal}
          appName={branding.appName ?? modal.appName}
          appLogo={branding.appLogo ?? modal.appLogo}
          appLogoSize={modal.appLogoSize}
          providers={
            socialRecovery?.enabled && socialRecovery.provider
              ? [socialRecovery.provider]
              : modal.providers
          }
          emailMode={
            socialRecovery?.enabled && socialRecovery.provider === 'email'
              ? 'magic-link'
              : modal.emailMode
          }
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

async function waitUntilWalletReady(wallet: CavosWallet): Promise<void> {
  const deadline = Date.now() + 90_000;
  for (;;) {
    try {
      if (await wallet.isReady()) return;
    } catch {
      // RPC/indexer propagation is eventually consistent; retry below.
    }
    if (Date.now() >= deadline) {
      throw new Error(
        "The recovery transaction was submitted, but the new signer is not visible yet.",
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 3_000));
  }
}

function pendingSocialRecoveryKey(chain: Chain, address: string): string {
  return `cavos-kit:social-recovery:${chain}:${address}`;
}

function persistPendingSocialRecovery(chain: Chain, address: string, readyAt: number): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(
    pendingSocialRecoveryKey(chain, address),
    JSON.stringify({ readyAt }),
  );
}

function loadPendingSocialRecovery(chain: Chain, address: string): number | null {
  if (typeof window === 'undefined') return null;
  try {
    const value = JSON.parse(
      window.localStorage.getItem(pendingSocialRecoveryKey(chain, address)) ?? 'null',
    );
    return Number.isFinite(value?.readyAt) ? Number(value.readyAt) : null;
  } catch {
    return null;
  }
}

function clearPendingSocialRecovery(chain: Chain, address: string): void {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(pendingSocialRecoveryKey(chain, address));
}

function socialRecoveryPrewarmKey(
  appId: string,
  environment?: 'development' | 'production',
): string {
  return `cavos-kit:social-recovery-prewarm:${appId}:${environment ?? 'production'}`;
}

function persistSocialRecoveryPrewarm(
  appId: string,
  environment: 'development' | 'production' | undefined,
  prewarm: SocialRecoveryPrewarm,
): void {
  if (typeof window === 'undefined') return;
  window.sessionStorage.setItem(
    socialRecoveryPrewarmKey(appId, environment),
    JSON.stringify(prewarm),
  );
}

function loadSocialRecoveryPrewarm(
  appId: string,
  environment?: 'development' | 'production',
): SocialRecoveryPrewarm | null {
  if (typeof window === 'undefined') return null;
  const key = socialRecoveryPrewarmKey(appId, environment);
  try {
    const value = JSON.parse(window.sessionStorage.getItem(key) ?? 'null');
    if (
      typeof value?.prewarmId === 'string' &&
      typeof value?.claimToken === 'string' &&
      typeof value?.expiresAt === 'string' &&
      new Date(value.expiresAt).getTime() > Date.now()
    ) {
      return value as SocialRecoveryPrewarm;
    }
  } catch {
    // Malformed browser state is discarded below.
  }
  window.sessionStorage.removeItem(key);
  return null;
}

function takeSocialRecoveryPrewarm(
  appId: string,
  environment?: 'development' | 'production',
): SocialRecoveryPrewarm | null {
  const prewarm = loadSocialRecoveryPrewarm(appId, environment);
  clearSocialRecoveryPrewarm(appId, environment);
  return prewarm;
}

function clearSocialRecoveryPrewarm(
  appId: string,
  environment?: 'development' | 'production',
): void {
  if (typeof window === 'undefined') return;
  window.sessionStorage.removeItem(socialRecoveryPrewarmKey(appId, environment));
}
