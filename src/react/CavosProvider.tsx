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
import type { Chain, NetworkEnv, CavosWallet, CavosSession } from '../Cavos';
import { PasskeyPrf } from '../chains/stellar/PasskeyPrf';
import { CavosAuth } from '../auth/CavosAuth';
import type { Identity } from '../auth/AuthProvider';
import type { ChainCall, ExecuteOptions } from '../chains/ChainAdapter';
import { assertDeviceApprovalScope } from './deviceApprovalScope';
import {
  resolveDeviceAuthorization,
  type DeviceApproval,
  type DeviceAuthorizationMethod,
} from './deviceAuthorization';
import { generateRecoveryCode } from '../recovery/recoveryCode';
import {
  shouldSkipSilentReconnect,
  urlHasOAuthCallbackCode,
} from './oauthCallback';
import {
  SocialRecoveryClient,
  type AttestationPolicy,
  type SocialRecoveryProvider,
} from '../recovery/SocialRecoveryClient';
import { DEFAULT_SOCIAL_RECOVERY_ATTESTATION } from '../recovery/attestationDefaults';
import { VaultClient } from '../vault/VaultClient';
import { zeroize } from '../secret/dek';
import { readLocalDek } from '../secret/localDek';
import { addPasskey } from '../secret/PasskeyDekPort';
import { HttpPasskeyWrapStore } from '../registry/PasskeyWrapStore';
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
  /**
   * Target chain (single-chain mode). Defaults to 'starknet'.
   * @deprecated Use `chains` and `defaultChain` for multi-chain sessions.
   * When `chains` is provided, this is ignored. If only `chain` is provided,
   * it's treated as `chains: [chain], defaultChain: chain`.
   */
  chain?: Chain;
  /**
   * Chains to configure for this session. Connect derives addresses for all
   * configured chains but NEVER deploys on connect. Deployment happens lazily
   * on the first `execute` call for each chain.
   */
  chains?: Chain[];
  /**
   * Default chain for the session. Must be in `chains`. When using the
   * single-chain `chain` option, `defaultChain` defaults to that chain.
   */
  defaultChain?: Chain;
  /** Environment: 'testnet' (sepolia/devnet) or 'mainnet'. */
  network: NetworkEnv;
  /**
   * Device-key slot. On native Solana/Stellar it is also the HKDF salt for the
   * spend key — never change it after users connect.
   */
  appSalt: string;
  /** Cavos paymaster API key (sponsors deploy + execute). Required for Starknet. */
  paymasterApiKey?: string;
  /** Override the Cavos auth backend (self-hosted / staging). */
  authBackendUrl?: string;
  /**
   * Whether a sign-in outlives the tab. Defaults to `true`: the identity is
   * kept in `localStorage` and the user stays signed in across tabs and
   * restarts. `false` keeps it in `sessionStorage` instead, so it survives a
   * reload and the OAuth redirect but ends when the tab closes; an identity
   * saved earlier in `localStorage` is removed.
   *
   * Read once, when the provider mounts. Changing it later has no effect until
   * the provider remounts (e.g. give it a new `key`). Only the built-in auth
   * uses it: with the `identity` prop your auth decides, and device keys stay
   * on the device either way.
   */
  persistSession?: boolean;
  /**
   * How a device that is not a signer yet gets authorized: by the attested
   * enclave, or by a passkey on the device. This is the app's choice — an app
   * runs one or the other, and inferring it at runtime gave different users
   * different flows. Defaults to the enclave when `socialRecovery` is on.
   */
  deviceApproval?: DeviceApproval;
  /** Override the chain RPC. Unambiguous only with a single configured chain. */
  rpcUrl?: string;
  /**
   * Per-chain RPC overrides, e.g. `{ solana: '…', starknet: '…' }`. Required
   * instead of `rpcUrl` once `chains` has more than one entry: one node cannot
   * serve them all, and the mismatched one answers "Method not found".
   */
  rpcUrls?: Partial<Record<Chain, string>>;
  /**
   * Where Toll lives, for `fee: { token }` — the user pays their own fee in a
   * token they already hold. Solana only. Omit it and that route is not offered.
   */
  tollUrl?: string;
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
   * Signing keys live in the Cavos vault, not in this page's
   * storage. On by default when `appId` is set; `false` turns it off.
   */
  vault?: boolean | { url?: string };
}

export interface CavosModalConfig {
  appName?: string;
  appLogo?: string;
  /** Logo height in px. Applies to both a custom `appLogo` (img) and the
   *  default Cavos star. Defaults to 40 (img) / 34 (star). */
  appLogoSize?: number;
  providers?: ('google' | 'apple' | 'email')[];
  primaryColor?: string;
  /** 'light' (default) or 'dark'. */
  theme?: 'light' | 'dark';
  /** Override the modal card background color (defaults to white/#111 per theme). */
  backgroundColor?: string;
  /** Card / button corner radius in px (card defaults to 16, buttons to 8). */
  radius?: number;
  /**
   * One-time "secure your account" step after a brand-new account is created.
   * Off by default: login never asks for a passkey. The app calls
   * `enrollPasskeyDefault` / `approveDeviceWithPasskey` when it wants that
   * prompt, or sets this to `'optional'` / `'required'` to use the modal's
   * built-in screen.
   */
  secureStep?: 'optional' | 'required' | 'off';
  onSuccess?: (address: string) => void;
}

/** Minimal wallet-status surface the React layer (and modal) needs. */
export interface WalletStatus {
  /** True while the account is being connected or deployed. */
  isDeploying: boolean;
  /** True once this device holds the wallet key. */
  isReady: boolean;
  /**
   * True if the account has not been deployed on-chain yet. First execute
   * will trigger deployment + the user operation atomically.
   */
  isUndeployed: boolean;
  /** True if this device still needs approval to operate the wallet. */
  needsDeviceApproval: boolean;
  /** True if the account has a passkey that can restore it on a new device. */
  hasPasskey: boolean;
  /** True right after a brand-new account is created (first sign-up), so the UI
   * can offer a one-time "secure your account" step. Cleared once handled. */
  isNewAccount: boolean;
  /**
   * Can this user get back in from a device they do not have yet?
   *
   * The one recovery question an app actually has to answer. The flags above
   * describe work in flight; this describes the standing guarantee, and it is
   * the only one most integrations need to read. `methods` is there so an app
   * can nudge — "add a passkey" reads better than "you are unprotected".
   *
   * `protected` is false until the lookup that fills it returns, so treat it as
   * "not known to be protected" rather than "known to be unprotected" during
   * the first moments of a connect.
   */
  recovery: {
    protected: boolean;
    methods: ('passkey' | 'social')[];
  };
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
  /** The currently selected chain ('starknet' | 'solana' | 'stellar'). */
  chain: Chain;
  /** All configured chains for this session. */
  configuredChains: Chain[];
  /**
   * Switch the selected chain. Must be one of the configured chains. Does not
   * re-deploy or re-authenticate — just changes which wallet is active.
   */
  setChain: (chain: Chain) => void;
  /**
   * The connected wallet for the selected chain, discriminated by `wallet.chain`.
   * Narrow on `wallet.chain` before chain-native calls (e.g. Solana
   * `wallet.execute(amount, dest)`). Null until connected.
   */
  wallet: CavosWallet | null;
  /**
   * The session containing wallets for all configured chains. Use this to access
   * wallets for chains other than the selected one: `session.wallet("solana")`.
   */
  session: (CavosWallet & CavosSession) | null;
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
  /** Email a 9-character sign-in code generated by the recovery enclave. */
  sendOtp: (email: string) => Promise<void>;
  /** Verify the emailed code inside the enclave and deploy the wallet. */
  verifyOtp: (email: string, code: string) => Promise<void>;
  /** Resolve identity from an OAuth callback (?auth_data=…) and deploy. */
  handleCallback: (authData: string) => Promise<void>;
  /**
   * Execute a multicall signed by the account key (Starknet-only — on Solana /
   * Stellar call `wallet.execute(...)` directly). Sponsored (gasless) by default;
   * pass `{ sponsored: false }` to submit directly with the account paying its
   * own fee.
   */
  execute: (calls: ChainCall[], opts?: ExecuteOptions) => Promise<{ transactionHash: string }>;
  /**
   * Sign an arbitrary message off-chain with the wallet's signing key. Chain-
   * agnostic (uniform `MessageSignature` return); delegates to
   * `wallet.signMessage` after narrowing on `wallet.chain`. See
   * [Signing](https://docs.cavos.xyz/docs/signing) for per-chain formats
   * and verification.
   */
  signMessage: (message: string | Uint8Array) => Promise<MessageSignature>;
  /** Whether this device can use a platform passkey (Face ID / Touch ID / PIN). */
  passkeySupported: boolean;
  /**
   * The single way this device should be authorized, when it is not a signer
   * yet. One decision taken before anything runs, so the UI shows one action
   * instead of racing every mechanism at once.
   */
  deviceAuthorization: DeviceAuthorizationMethod;
  /**
   * Authorize this device on the wallet, by whichever route
   * `deviceAuthorization` chose. Called for you before any action that needs
   * the account's authority; call it directly to do it ahead of time.
   */
  authorizeDevice: () => Promise<void>;
  /**
   * True while an authorization is being asked for. The modal shows the flow
   * only then — signing in must not be interrupted by a device that is merely
   * not a signer yet, the same way a wallet is not deployed until it is used.
   */
  authorizingDevice: boolean;
  /**
   * Modal-friendly wrapper: add a synced passkey that restores the wallet on a
   * new device, using the signed-in user's identity + the app name. Requires a
   * ready device.
   */
  enrollPasskeyDefault: () => Promise<void>;
  /**
   * Modal-friendly wrapper for the new-device flow: prompt the user's synced
   * passkey to restore the wallet key on THIS device, then refresh to a ready state.
   */
  approveDeviceWithPasskey: () => Promise<void>;
  /**
   * Stellar only: register a backup signer derived from a generated recovery
   * code (gasless). Resolves with the code so the caller can display it once.
   */
  setupRecovery: () => Promise<string>;
  /**
   * Stellar only: recover access after losing every device with the recovery
   * code. Brings the provider to a ready state.
   */
  recover: (code: string) => Promise<void>;
  /**
   * Drive social recovery with a provider id_token your own login already
   * obtained, so the user never signs in twice.
   *
   * Reconnects the wallet with that proof, so the enclave seals a new wallet or
   * restores this device onto an existing one. Pass the raw Google or Apple
   * `id_token`, not your own session JWT, and pass it straight from a sign-in:
   * the enclave requires the authentication to be under five minutes old.
   *
   * Requires the app's own OAuth client ID to be registered for the environment
   * in the dashboard, so the enclave accepts tokens minted for your client.
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
  isUndeployed: false,
  needsDeviceApproval: false,
  hasPasskey: false,
  isNewAccount: false,
  recovery: { protected: false, methods: [] },
};

interface SocialRecoveryEnvironment {
  enabled: boolean;
  provider: SocialRecoveryProvider | null;
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
 * derives the account key from a MasterDEK, and the wallet handle submits
 * gasless transactions signed silently by that key.
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

function vaultSetting(config: CavosConfig): boolean | { url?: string } {
  return config.vault ?? Boolean(config.appId);
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

  const socialRecoveryPolicy = useMemo(
    () => resolveSocialRecoveryPolicy(config),
    [config.socialRecovery, config.socialRecoveryAttestation],
  );
  const [auth] = useState(
    () =>
      new CavosAuth({
        appId: config.appId,
        backendUrl: config.authBackendUrl,
        persistSession: config.persistSession,
        attestation: socialRecoveryPolicy,
      }),
  );
  const [session, setSession] = useState<(CavosWallet & CavosSession) | null>(null);
  const [selectedChain, setSelectedChain] = useState<Chain>(
    config.chains?.[0] ?? config.defaultChain ?? config.chain ?? 'starknet',
  );
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [walletStatus, setWalletStatus] = useState<WalletStatus>(INITIAL_STATUS);

  // The selected chain is seeded from the config once, so an app that changes
  // which chains it configures -- switching to passkey approval makes the
  // session single-chain -- was left pointing at a chain no longer in it. The
  // lookup then threw and fell back to the default wallet, so the app showed
  // one chain and acted on another.
  useEffect(() => {
    const configured = config.chains ?? (config.chain ? [config.chain] : ['starknet']);
    if (!configured.includes(selectedChain)) setSelectedChain(configured[0]!);
  }, [config.chains, config.chain, selectedChain]);

  // Derive the active wallet from the session and selected chain
  const wallet = useMemo<CavosWallet | null>(() => {
    if (!session) return null;
    try {
      return session.wallet(selectedChain);
    } catch {
      // If the selected chain is not in the session, fall back to the default
      return session;
    }
  }, [session, selectedChain]);
  // Keep children behind the loading state until we have checked for a
  // persisted identity and silently reconnected this browser's device signer.
  const [isLoading, setIsLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [passkeySupported, setPasskeySupported] = useState(false);
  const [authorizingDevice, setAuthorizingDevice] = useState(false);
  /** Set when an authorization attempt fails, so a wait can end on it. */
  const authorizationErrorRef = useRef<string | null>(null);
  // Held in a ref so the wallets can be wired once, rather than re-subscribed
  // every time the callback identity changes.
  const authorizeDeviceRef = useRef<() => Promise<void>>(async () => {});
  /**
   * Which wallets already hold a recovery authority, keyed by chain and
   * address.
   *
   * This was one boolean for the whole session. Enrolling on one chain set it,
   * and every other chain was then skipped as "already enrolled" — so a user
   * who enrolled Solana got a Starknet wallet with no authority at all, and
   * found out only when a second device could not recover it.
   */
  const socialEnrolledRef = useRef(new Set<string>());
  const [socialRecovery, setSocialRecovery] =
    useState<SocialRecoveryEnvironment | null>(null);
  /** App name/logo fetched from the backend; overrides manual modal props when present. */
  const [branding, setBranding] = useState<{ appName?: string; appLogo?: string }>({});
  /**
   * Set before `replaceState` strips the OAuth callback code from the URL, so
   * the silent-reconnect effect — which otherwise runs in the same tick and
   * sees a clean URL — does not restore the previous localStorage identity
   * without a login token.
   */
  const oauthCallbackInFlightRef = useRef(false);

  // Detect platform-passkey support once, so the modal can hide passkey options
  // on devices/browsers that can't offer them.
  useEffect(() => {
    let cancelled = false;
    PasskeyPrf.isSupported()
      .then((ok) => { if (!cancelled) setPasskeySupported(ok); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // Keep the latest config for callbacks that run after async gaps.
  const configRef = useRef(config);
  useEffect(() => {
    configRef.current = config;
  });

  // Mount the vault iframe now rather than when connect first asks for it.
  // `attach` is memoized, so connect later reuses this one — already loaded
  // while the OAuth code exchange ran, instead of loading after it.
  useEffect(() => {
    const vault = vaultSetting(config);
    if (!vault || !config.appId || typeof window === 'undefined') return;
    VaultClient.attach({ appId: config.appId, ...(typeof vault === 'object' ? vault : {}) });
  }, [config.appId, config.vault]);

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
        });
      })
      .catch(() => setSocialRecovery({ enabled: false, provider: null }));
  }, [config.appId, config.environment, config.authBackendUrl]);

  /**
   * Resolve the standing recovery guarantee once the wallet is known: does it
   * carry a passkey, and is it enrolled with the enclave. Both are cheap reads
   * and both are best-effort — a wallet whose recovery state cannot be read is
   * reported as unprotected, which is the safe direction to be wrong in.
   *
   * This also feeds the enrolment effect below, which uses it to skip a wallet
   * that is already enrolled instead of running the enclave to be told 409.
   */
  useEffect(() => {
    if (!wallet || !config.appId) return;
    let cancelled = false;

    (async () => {
      const [passkey, social] = await Promise.all([
        wallet.hasPasskey().catch(() => false),
        (async () => {
          const base = config.authBackendUrl ?? 'https://cavos.xyz';
          const query = new URLSearchParams({
            app_id: config.appId!,
            wallet_address: wallet.address,
            ...(config.environment ? { environment: config.environment } : {}),
          });
          try {
            const res = await fetch(`${base}/api/recovery/social/enrollment?${query}`);
            if (!res.ok) return false;
            return (await res.json()).enrolled === true;
          } catch {
            return false;
          }
        })(),
      ]);
      if (cancelled) return;
      if (social) socialEnrolledRef.current.add(`${wallet.chain}:${wallet.address}`);
      else socialEnrolledRef.current.delete(`${wallet.chain}:${wallet.address}`);
      const methods: ('passkey' | 'social')[] = [];
      // Passkey first: it needs no round trip to the enclave.
      if (passkey) methods.push('passkey');
      if (social) methods.push('social');
      setWalletStatus((status) => ({
        ...status,
        hasPasskey: status.hasPasskey || passkey,
        recovery: { protected: methods.length > 0, methods },
      }));
    })();

    return () => { cancelled = true; };
  }, [wallet, config.appId, config.environment, config.authBackendUrl]);

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

  // One decision, taken before anything runs. Passkey first (instant, needs
  // nothing else), then the enclave, then email — which needs a second device
  // and the user's attention twice, so it is the floor rather than the default
  // it used to be.
  //
  // The app's choice is one value. Login never asks for a passkey; that
  // prompt is enrollPasskeyDefault / approveDeviceWithPasskey.
  const appDeviceApproval = useMemo(
    () =>
      (config.deviceApproval
        ?? (resolveSocialRecoveryPolicy(config) ? 'enclave' : 'passkey')) as DeviceApproval,
    [config.deviceApproval, config.socialRecovery, config.socialRecoveryAttestation],
  );
  const deviceAuthorization = useMemo(
    () => {
      assertDeviceApprovalScope(
        appDeviceApproval,
        config.chains ?? (config.chain ? [config.chain] : ['starknet']),
      );
      return resolveDeviceAuthorization({
        approval: appDeviceApproval,
        socialCredential: auth.hasSocialRecoveryCredential(),
        chain: wallet?.chain,
      });
    },
    [
      appDeviceApproval,
      config.chains,
      config.chain,
      auth,
      identity,
      wallet?.chain,
    ],
  );


  // The wallet turning ready is what ends an authorization, whoever performed it.
  useEffect(() => {
    if (walletStatus.isReady) setAuthorizingDevice(false);
  }, [walletStatus.isReady]);

  // Connect the configured chains for an identity (deploys if needed), then
  // publish the status for the default chain. `silent` reconnects keep the
  // current screen instead of resetting to the deploying state (used right
  // after a passkey approval).
  const connect = useCallback(async (id: Identity, opts?: { silent?: boolean; passkey?: boolean }): Promise<CavosWallet & CavosSession> => {
    // A wall clock on the whole thing. `fetch` has no timeout of its own, so a
    // stalled request — a phone that changed network, a tab that was
    // backgrounded, an RPC that accepted the connection and went quiet — leaves
    // an await that never settles. No error handler helps with that: there is no
    // error. The spinner simply stays up forever, which is what it did.
    const CONNECT_TIMEOUT_MS = 45_000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error('Connecting timed out. Check your connection and try again.')),
        CONNECT_TIMEOUT_MS,
      );
    });

    // Everything below runs inside a try: the deploying flag is set at the top
    // and cleared at the bottom, so a throw in between leaves it true for the
    // life of the page. Every failure then looks the same — a spinner that
    // never resolves, on a device with no console to ask — which is how a
    // registry 401 and a chain that will not connect became indistinguishable.
    try {
      const cfg = configRef.current;
      if (!opts?.silent) setWalletStatus({ ...INITIAL_STATUS, isDeploying: true });
      // Anything awaited below races the deadline above.
      const race = <T,>(work: Promise<T>): Promise<T> => Promise.race([work, deadline]);

      // Resolve chains configuration: use new `chains`/`defaultChain` if provided,
      // otherwise fall back to single `chain` for back-compat
      const connectOpts = cfg.chains
        ? { chains: cfg.chains, defaultChain: cfg.defaultChain }
        : { chain: cfg.chain ?? 'starknet' as Chain };

      const socialPolicy = resolveSocialRecoveryPolicy(cfg);
      const socialClient =
        cfg.appId && socialPolicy
          ? new SocialRecoveryClient({
              baseUrl: cfg.authBackendUrl ?? 'https://cavos.xyz',
              appId: cfg.appId,
              environment: cfg.environment,
              attestation: socialPolicy,
            })
          : undefined;
      const socialCredential = auth.hasSocialRecoveryCredential()
        ? auth.consumeSocialRecoveryCredential()
        : undefined;
      // In the vault, a passkey app offers the passkey whenever this device
      // lacks the key of a wallet that exists. The vault only asks then: a new
      // account is created without one, and a device that has the key never
      // sees the prompt.
      const vaultOn = Boolean(vaultSetting(cfg)) && Boolean(cfg.appId);
      const passkeyPrf =
        opts?.passkey || (vaultOn && appDeviceApproval === 'passkey')
          ? new PasskeyPrf({
              rpName: branding.appName ?? modal?.appName ?? 'Cavos',
              ...(cfg.rpId ? { rpId: cfg.rpId } : {}),
            })
          : undefined;

      const s = await race(Cavos.connect({
        ...connectOpts,
        network: cfg.network,
        identity: id,
        // The registry authenticates the end user with this login's token.
        auth,
        appSalt: cfg.appSalt,
        ...(cfg.paymasterApiKey ? { paymasterApiKey: cfg.paymasterApiKey } : {}),
        ...(cfg.appId ? { appId: cfg.appId } : {}),
        ...(cfg.environment ? { environment: cfg.environment } : {}),
        ...(cfg.authBackendUrl ? { backendUrl: cfg.authBackendUrl } : {}),
        ...(cfg.rpcUrl ? { rpcUrl: cfg.rpcUrl } : {}),
        ...(cfg.rpcUrls ? { rpcUrls: cfg.rpcUrls } : {}),
        ...(cfg.tollUrl ? { tollUrl: cfg.tollUrl } : {}),
        ...(socialClient ? { socialRecovery: socialClient } : {}),
        ...(socialCredential ? { socialRecoveryCredential: socialCredential } : {}),
        ...(passkeyPrf ? { passkeyPrf } : {}),
        vault: vaultSetting(cfg),
      }));
      setSession(s);
      setSelectedChain(s.defaultChain);
      setIdentity(id);

      // Get the default wallet for status updates
      const w = s.wallet(s.defaultChain);

      let hasPasskey = false;
      if (w.status === 'needs-device-approval' || w.status === 'undeployed') {
        // Also raced: this reads the chain, so it can stall like anything else,
        // and a hang here would strand the connect just as completely.
        try { hasPasskey = await race(w.hasPasskey()); } catch { hasPasskey = false; }
      }

      setWalletStatus({
        isDeploying: false,
        isReady: w.status === 'ready',
        isUndeployed: w.status === 'undeployed',
        needsDeviceApproval: w.status === 'needs-device-approval',
        hasPasskey,
        isNewAccount: w.isNewAccount,
        // Unknown until the lookup above answers for this wallet.
        recovery: { protected: false, methods: [] },
      });
      modal?.onSuccess?.(w.address);
      return s;
    } catch (error) {
      setWalletStatus((status) => ({ ...status, isDeploying: false }));
      setAuthError(error instanceof Error ? error.message : 'Could not connect your wallet.');
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }, [modal, appDeviceApproval, branding.appName]);

  const handleCallback = useCallback(async (authData: string, redirectUri?: string) => {
    const id = await auth.handleCallback(authData, redirectUri);
    await connect(id);
  }, [auth, connect]);

  // Switch the selected chain without re-authenticating
  const setChain = useCallback(async (chain: Chain) => {
    if (!session) {
      throw new Error('kit/react: cannot setChain before connecting');
    }
    if (!session.chains.includes(chain)) {
      throw new Error(`kit/react: chain "${chain}" is not configured in this session. Configured chains: [${session.chains.join(', ')}]`);
    }
    setSelectedChain(chain);

    // Update wallet status for the new chain
    const w = session.wallet(chain);
    let hasPasskey = false;
    if (w.status === 'needs-device-approval' || w.status === 'undeployed') {
      try { hasPasskey = await w.hasPasskey(); } catch { hasPasskey = false; }
    }

    setWalletStatus((status) => ({
      ...status,
      isReady: w.status === 'ready',
      isUndeployed: w.status === 'undeployed',
      needsDeviceApproval: w.status === 'needs-device-approval',
      hasPasskey,
      isNewAccount: w.isNewAccount,
    }));
  }, [session]);

  // On mount: exchange the one-time OAuth code after removing it from the
  // address bar immediately. Legacy auth_data is accepted only for callbacks
  // already in flight during rollout.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const authData = params.get('cavos_auth_code') || params.get('auth_data') || params.get('zk_auth_data');
    if (!authData) return;
    // Claim the callback before cleaning the URL. Silent reconnect checks this
    // ref in the same tick and would otherwise reconnect the previous identity
    // with no Bearer token (registry 401).
    oauthCallbackInFlightRef.current = true;
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


  // The first execute deploys the account and flips the wallet to ready by
  // mutating it, which re-renders nothing. Without this the provider kept
  // reporting the wallet as undeployed after a successful send, and the effect
  // below — which enrols recovery once a wallet is ready — never re-ran.
  useEffect(() => {
    if (!session) return;
    const resync = () => {
      const w = session.wallet(selectedChain);
      setWalletStatus((status) => ({
        ...status,
        isReady: w.status === 'ready',
        isUndeployed: w.status === 'undeployed',
        needsDeviceApproval: w.status === 'needs-device-approval',
        isNewAccount: w.isNewAccount,
      }));
    };
    const unsubscribes = session.chains.map((c) => session.wallet(c).onStatusChange(resync));

    // The wallets refuse an unauthorized device wherever the action is called
    // from — including `wallet.execute` straight from the app, which no wrapper
    // here would ever see. This is how that refusal reaches the UI.
    for (const c of session.chains) {
      const w = session.wallet(c);
      w.onAuthorizationNeeded = () => authorizeDeviceRef.current();
    }

    return () => {
      unsubscribes.forEach((off) => off());
      for (const c of session.chains) {
        const w = session.wallet(c);
        w.onAuthorizationNeeded = undefined;
      }
    };
  }, [session, selectedChain]);

  // A device signer is already persisted securely in IndexedDB. Restore only
  // the non-secret identity metadata from localStorage, then reconnect the
  // existing signer without another OAuth prompt.
  useEffect(() => {
    if (typeof window === "undefined") return;
    // Under external auth the host's identity is the only source of truth, and
    // it is never written to storage. Restoring here would resurrect a session
    // the host may have already ended.
    if (isExternalAuth) return;
    if (
      shouldSkipSilentReconnect({
        oauthCallbackInFlight: oauthCallbackInFlightRef.current,
        urlHasAuthCode: urlHasOAuthCallbackCode(window.location.search),
      })
    ) {
      return;
    }

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
      setSession(null);
      setIdentity(null);
      setWalletStatus(INITIAL_STATUS);
      setAuthError(null);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    // Clear the outgoing user's wallet before connecting the incoming one, so
    // a slow connect cannot briefly expose the wrong account.
    setSession(null);
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
    const url = await (provider === 'google'
      ? auth.getGoogleOAuthUrl(window.location.origin + window.location.pathname)
      : auth.getAppleOAuthUrl(window.location.origin + window.location.pathname));
    window.location.href = url;
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
    // The wallet authorizes the device itself when the call needs it, and then
    // performs the call -- one flow, so there is nothing to check first.
    return wallet.execute(calls, opts);
  }, [wallet]);

  // Chain-agnostic off-chain message signing. Every chain's wallet exposes the
  // same `signMessage(message)` signature returning a uniform `MessageSignature`.
  const signMessage = useCallback(
    async (message: string | Uint8Array): Promise<MessageSignature> => {
      if (!wallet) throw new Error('Not logged in');
      // Same rule as execute. A signature from a key the account does not
      // recognise is one nobody will accept, so producing it would only look
      // like success.
      if (wallet.status === 'needs-device-approval') {
        await authorizeDeviceRef.current();
      }
      return wallet.signMessage(message);
    },
    [wallet],
  );

  const rpName = branding.appName ?? modal?.appName ?? 'Cavos';

  /**
   * Add a passkey that restores the wallet on a new device, with one gesture.
   *
   * Success means a copy of the DEK is stored under the passkey. A passkey that
   * merely exists would restore nothing on the next device. Every chain in the
   * session derives from the same DEK, so one passkey covers them all.
   */
  const enrollPasskeyDefault = useCallback(async () => {
    if (!session || !identity) throw new Error('Not logged in');
    const cfg = configRef.current;
    if (!cfg.appId) throw new Error('kit: adding a passkey requires an appId');
    const vault = vaultSetting(cfg);
    const user = { userId: identity.userId, userName: identity.email ?? identity.userId };
    const authToken = auth.getAuthToken();
    if (vault) {
      await VaultClient.attach({ appId: cfg.appId, ...(typeof vault === 'object' ? vault : {}) }).enrollPasskey({
        ...user,
        appSalt: cfg.appSalt,
        ...(cfg.environment ? { environment: cfg.environment } : {}),
        authToken,
      });
    } else {
      const w = session.chains.map((c) => session.wallet(c)).find((x) => x.status !== 'needs-device-approval');
      if (!w) {
        throw new Error('kit: this device does not hold the wallet key, so it cannot add a passkey');
      }
      const dek = await readLocalDek({ chain: w.chain, userId: identity.userId, appSalt: cfg.appSalt, address: w.address });
      try {
        await addPasskey({
          passkey: new PasskeyPrf({ rpName, ...(cfg.rpId ? { rpId: cfg.rpId } : {}) }),
          wraps: new HttpPasskeyWrapStore({
            baseUrl: cfg.authBackendUrl ?? 'https://cavos.xyz',
            appId: cfg.appId,
            ...(cfg.environment ? { environment: cfg.environment } : {}),
            authToken: () => auth.getAuthToken(),
          }),
          owner: { appId: cfg.appId, userId: identity.userId },
          dek,
          user,
        });
      } finally {
        zeroize(dek);
      }
    }
    setWalletStatus((status) => ({ ...status, hasPasskey: true }));
  }, [session, identity, rpName, auth]);

  // New-device flow: ONE passkey prompt approves THIS device on the connected
  // chain, then poll readiness and reconnect once.
  const approveDeviceWithPasskey = useCallback(async () => {
    if (!wallet || !identity) throw new Error('Not logged in');
    if (wallet.chain !== 'stellar' || wallet.nativeDek) {
      await connect(identity, { passkey: true });
      return;
    }
    if (wallet.status !== 'needs-device-approval') {
      await connect(identity, { passkey: true });
      return;
    }
    const prf = new PasskeyPrf({ rpName });
    await wallet.approveThisDeviceWithPasskey(await prf.getSecret());
    // The on-chain add_signer isn't indexed the instant the tx submits — show the
    // deploying state and poll readiness (cheap, side-effect free) until it lands.
    setWalletStatus((s) => ({ ...s, isDeploying: true, needsDeviceApproval: false }));
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

  // Authorization is lazy, like deployment. Signing in on a new device does not
  // interrupt anyone: reads work without being a signer, so the wallet shows
  // its address and balance straight away. Only an action that needs the
  // account's authority asks — at a moment the user is already acting, where
  // the request explains itself.
  /** Resolve once the wallet accepts this device, or give up saying so. */
  const waitUntilAuthorized = useCallback(
    (w: CavosWallet, timeoutMs = 90_000) =>
      new Promise<void>((resolve, reject) => {
        if (w.status === 'ready') return resolve();
        authorizationErrorRef.current = null;
        const timer = setTimeout(() => {
          stop();
          reject(new Error('Authorizing this device took too long. Try again.'));
        }, timeoutMs);
        // A wallet with no recovery authority is refused in a second — waiting
        // out the full timeout to say so is a minute and a half of nothing.
        const poll = setInterval(() => {
          if (!authorizationErrorRef.current) return;
          const message = authorizationErrorRef.current;
          stop();
          reject(new Error(message));
        }, 250);
        const off = w.onStatusChange(() => {
          if (w.status !== 'ready') return;
          stop();
          resolve();
        });
        function stop() {
          clearTimeout(timer);
          clearInterval(poll);
          off();
        }
      }),
    [],
  );

  const authorizeDevice = useCallback(async () => {
    if (!wallet || wallet.status !== 'needs-device-approval') return;
    setAuthorizingDevice(true);
    try {
      // Do the thing, rather than open a screen asking to do the thing. Most of
      // these need nothing from the user: the enclave runs on its own, and an
      // approval email is a request, not a dialog. Only a passkey needs a
      // gesture, and only a missing login proof needs the user at all.
      switch (deviceAuthorization) {
        case 'passkey':
          // WebAuthn needs a tap the send already spent, so hand the user the
          // passkey screen and let them send again once it is done.
          if (walletStatus.hasPasskey) {
            openModal();
            throw new Error('Verify it\'s you with your passkey to use this device, then try again.');
          }
          throw new Error(
            'This device is not authorized yet. Add a passkey on a device that is, then sign in here again.',
          );
        case 'enclave': {
          // Waiting is only worth it if there is something to wait for. A
          // wallet with no authority on-chain cannot be recovered, and the
          // attempt that proved it is deduplicated — so nothing would fail
          // again and the wait would sit out its whole timeout in silence.
          if (!socialEnrolledRef.current.has(`${wallet.chain}:${wallet.address}`)) {
            throw new Error(
              'This wallet has no recovery set up, so this device cannot be restored. ' +
                'Open it on the device that created it and it will be set up there.',
            );
          }
          // The effect below starts it as soon as a wallet needing
          // authorization meets a live login proof; this waits for the outcome,
          // so the action that asked can carry straight on.
          await waitUntilAuthorized(wallet);
          break;
        }
        case 'enclave-needs-login':
          setAuthError('Sign in again to restore this device.');
          break;
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'Could not authorize this device.');
      // And let it reach whoever asked. Swallowing it left the caller to infer
      // the failure from a status that had not moved, so an execute reported
      // "this device was not authorized" over any real reason -- a timeout, a
      // refused recovery, a declined passkey.
      throw error;
    } finally {
      setAuthorizingDevice(false);
    }
  }, [wallet, deviceAuthorization, waitUntilAuthorized, walletStatus.hasPasskey, openModal]);

  authorizeDeviceRef.current = authorizeDevice;

  // Generate a recovery code and register its derived backup signer (gasless).
  // The code is returned so the UI can display it once — never persisted.
  const setupRecovery = useCallback(async (): Promise<string> => {
    if (!wallet) throw new Error('Not logged in');
    if (wallet.chain !== 'stellar') {
      throw new Error('kit: recovery codes are Stellar-only; use a passkey or the enclave on other chains.');
    }
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
      const chain = cfg.chain ?? cfg.defaultChain ?? cfg.chains?.[0] ?? 'starknet';
      if (chain === 'stellar') {
        // Classic `G…`: reconnect this (fresh) device, then use the recovery code
        // to approve it — the code unlocks the control key which authorizes adding
        // this device's slot. The account already exists, so no funder is needed.
        const sw = await Cavos.connect({
          chain: 'stellar',
          network: cfg.network,
          identity,
          auth,
          appSalt: cfg.appSalt,
          ...(cfg.appId ? { appId: cfg.appId } : {}),
          ...(cfg.authBackendUrl ? { backendUrl: cfg.authBackendUrl } : {}),
        });
        if (sw.chain === 'stellar' && sw.status === 'needs-device-approval') {
          await sw.approveThisDeviceWithRecovery(code);
        }
      }
      // After recovery, reconnect to get a proper session with all chains
      await connect(identity);
      modal?.onSuccess?.(wallet?.address ?? '');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Recovery failed. Check your code and try again.';
      setAuthError(msg);
      setWalletStatus(INITIAL_STATUS);
      throw e;
    }
  }, [identity, modal, connect, wallet]);

  const submitSocialRecoveryToken = useCallback((idToken: string) => {
    // Throws for a token no provider the enclave trusts could have issued, so
    // the mistake surfaces here instead of as an opaque enclave rejection.
    auth.useExternalSocialRecoveryToken(idToken);
    if (identity) void connect(identity, { silent: true });
  }, [auth, identity, connect]);

  const logout = useCallback(() => {
    const vault = vaultSetting(config);
    if (vault && config.appId && identity) {
      VaultClient.attach({ appId: config.appId, ...(typeof vault === 'object' ? vault : {}) })
        .forget(identity.userId, config.appSalt)
        .catch(() => undefined);
    }
    auth.clearStoredIdentity();
    setSession(null);
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
  }, [auth, config, identity, isExternalAuth]);

  const value: CavosContextValue = {
    openModal,
    closeModal,
    isAuthenticated: !!session,
    user: identity
      ? { userId: identity.userId, email: identity.email, name: identity.name, provider: identity.provider }
      : null,
    chain: selectedChain,
    configuredChains: session?.chains ?? [config.chains?.[0] ?? config.defaultChain ?? config.chain ?? 'starknet'],
    setChain,
    wallet,
    session,
    address: wallet?.address ?? null,
    walletStatus,
    isLoading,
    authError,
    clearAuthError,
    login,
    sendOtp,
    verifyOtp,
    handleCallback,
    execute,
    signMessage,
    passkeySupported,
    deviceAuthorization,
    authorizeDevice,
    authorizingDevice,
    enrollPasskeyDefault,
    approveDeviceWithPasskey,
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
