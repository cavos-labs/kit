import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { Identity } from "../auth/AuthProvider";
import type { Chain, CavosWallet, NetworkEnv } from "../Cavos";
import type { ChainCall, ExecuteOptions } from "../chains/ChainAdapter";
import type { MessageSignature } from "../signing";
import { generateRecoveryCode } from "../recovery/BackupSigner";
import { HttpRecoveryClient } from "../recovery/HttpRecoveryClient";
import { Cavos, type NativeConnectOptions } from "./CavosNative";
import { NativeCavosAuth } from "./NativeCavosAuth";
import { NativePasskeyPrf, NativePasskeySigner } from "./NativePasskeys";
import { nativeModule, type NativeCapabilities } from "./NativeModule";
import type { MinimumKeySecurity } from "./NativeDeviceSigner";
import { CavosAuthModal } from "./CavosAuthModal";

export interface CavosConfig {
  appId: string;
  environment?: "development" | "production";
  chain?: Chain;
  network: NetworkEnv;
  appSalt: string;
  paymasterApiKey?: string;
  authBackendUrl?: string;
  rpcUrl?: string;
  redirectUri: string;
  rpId: string;
  minimumKeySecurity?: MinimumKeySecurity;
}

export interface CavosModalConfig {
  appName?: string;
  providers?: ("google" | "apple" | "email")[];
  emailMode?: "magic-link" | "otp";
  secureStep?: "optional" | "required" | "off";
  primaryColor?: string;
  onSuccess?: (address: string) => void;
}

export interface WalletStatus {
  isDeploying: boolean;
  isReady: boolean;
  needsDeviceApproval: boolean;
  awaitingApproval: boolean;
  pendingRequestId: string | null;
  hasPasskey: boolean;
  isNewAccount: boolean;
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

export interface CavosContextValue {
  openModal(): void;
  closeModal(): void;
  isAuthenticated: boolean;
  user: Identity | null;
  chain: Chain;
  wallet: CavosWallet | null;
  address: string | null;
  walletStatus: WalletStatus;
  capabilities: NativeCapabilities | null;
  isLoading: boolean;
  authError: string | null;
  clearAuthError(): void;
  login(provider: "google" | "apple"): Promise<void>;
  sendMagicLink(email: string): Promise<void>;
  sendOtp(email: string): Promise<void>;
  verifyOtp(email: string, code: string): Promise<void>;
  handleCallback(url: string): Promise<void>;
  execute(calls: ChainCall[], opts?: ExecuteOptions): Promise<{ transactionHash: string }>;
  signMessage(message: string | Uint8Array): Promise<MessageSignature>;
  enrollPasskeyDefault(): Promise<void>;
  approveDeviceWithPasskey(): Promise<void>;
  setupRecovery(): Promise<string>;
  recover(code: string): Promise<void>;
  resendDeviceApproval(): Promise<void>;
  logout(): Promise<void>;
}

const Context = createContext<CavosContextValue | null>(null);

export function CavosProvider(props: { config: CavosConfig; modal?: CavosModalConfig; children: ReactNode }) {
  const { config, modal, children } = props;
  const configRef = useRef(config);
  configRef.current = config;
  const auth = useMemo(() => new NativeCavosAuth({
    appId: config.appId,
    redirectUri: config.redirectUri,
    backendUrl: config.authBackendUrl,
  }), [config.appId, config.redirectUri, config.authBackendUrl]);
  const [wallet, setWallet] = useState<CavosWallet | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [status, setStatus] = useState(INITIAL_STATUS);
  const [isLoading, setLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [capabilities, setCapabilities] = useState<NativeCapabilities | null>(null);

  const connect = useCallback(async (id: Identity): Promise<CavosWallet> => {
    const cfg = configRef.current;
    setStatus({ ...INITIAL_STATUS, isDeploying: true });
    const opts: NativeConnectOptions = {
      chain: cfg.chain ?? "starknet",
      network: cfg.network,
      identity: id,
      appSalt: cfg.appSalt,
      appId: cfg.appId,
      environment: cfg.environment,
      backendUrl: cfg.authBackendUrl,
      rpcUrl: cfg.rpcUrl,
      paymasterApiKey: cfg.paymasterApiKey,
      minimumKeySecurity: cfg.minimumKeySecurity,
    };
    const next = await Cavos.connect(opts);
    let hasPasskey = false;
    if (next.status === "needs-device-approval") {
      try { hasPasskey = await next.hasPasskey(); } catch { /* factor is optional */ }
    }
    const pendingRequestId = next.chain === "starknet" || next.chain === "solana"
      ? next.pendingRequestId
      : null;
    setWallet(next);
    setIdentity(id);
    setStatus({
      isDeploying: false,
      isReady: next.status === "ready",
      needsDeviceApproval: next.status === "needs-device-approval",
      awaitingApproval: next.status === "needs-device-approval" && !!pendingRequestId,
      pendingRequestId,
      hasPasskey,
      isNewAccount: next.isNewAccount,
    });
    modal?.onSuccess?.(next.address);
    return next;
  }, [modal]);

  useEffect(() => {
    let active = true;
    Promise.all([nativeModule().getCapabilities(), auth.restoreIdentity()])
      .then(async ([caps, saved]) => {
        if (!active) return;
        setCapabilities(caps);
        if (saved) await connect(saved);
      })
      .catch((error) => active && setAuthError(messageOf(error)))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [auth, connect]);

  const finishIdentity = useCallback(async (id: Identity) => {
    setAuthError(null);
    setLoading(true);
    try { await connect(id); } finally { setLoading(false); }
  }, [connect]);

  const login = useCallback(async (provider: "google" | "apple") => {
    try { await finishIdentity(await auth.login(provider)); }
    catch (error) { setAuthError(messageOf(error)); throw error; }
  }, [auth, finishIdentity]);

  const verifyOtp = useCallback(async (email: string, code: string) => {
    try { await finishIdentity(await auth.verifyOtp(email, code)); }
    catch (error) { setAuthError(messageOf(error)); throw error; }
  }, [auth, finishIdentity]);

  const handleCallback = useCallback(async (url: string) => {
    try { await finishIdentity(await auth.handleCallback(url)); }
    catch (error) { setAuthError(messageOf(error)); throw error; }
  }, [auth, finishIdentity]);

  const execute = useCallback(async (calls: ChainCall[], opts?: ExecuteOptions) => {
    if (!wallet || wallet.chain !== "starknet") {
      throw new Error("kit/native: context execute is Starknet-only; use the typed wallet on Solana or Stellar");
    }
    return wallet.execute(calls, opts);
  }, [wallet]);

  const signMessage = useCallback(async (message: string | Uint8Array) => {
    if (!wallet) throw new Error("kit/native: not connected");
    return wallet.signMessage(message);
  }, [wallet]);

  const enrollPasskeyDefault = useCallback(async () => {
    if (!wallet || !identity || wallet.status !== "ready") throw new Error("kit/native: ready wallet required");
    const rpName = modal?.appName ?? "Cavos";
    if (wallet.chain === "stellar") {
      const passkey = new NativePasskeyPrf({ rpId: config.rpId, rpName });
      const result = await passkey.enroll({
        userId: identity.userId,
        userName: identity.email ?? identity.userId,
      });
      await wallet.enrollPasskey(result.secret ?? await passkey.getSecret());
    } else {
      const passkey = new NativePasskeySigner({ rpId: config.rpId, rpName });
      await wallet.enrollPasskey(passkey, {
        userId: identity.userId,
        userName: identity.email ?? identity.userId,
      });
    }
  }, [wallet, identity, modal?.appName, config.rpId]);

  const approveDeviceWithPasskey = useCallback(async () => {
    if (!wallet || !identity) throw new Error("kit/native: sign in first");
    const rpName = modal?.appName ?? "Cavos";
    if (wallet.chain === "stellar") {
      const passkey = new NativePasskeyPrf({ rpId: config.rpId, rpName });
      await wallet.approveThisDeviceWithPasskey(await passkey.getSecret());
    } else {
      const passkey = new NativePasskeySigner({ rpId: config.rpId, rpName });
      if (wallet.chain === "starknet") await wallet.approveThisDeviceWithPasskey({ passkey });
      else await wallet.approveThisDeviceWithPasskey(passkey);
    }
    await connect(identity);
  }, [wallet, identity, modal?.appName, config.rpId, connect]);

  const setupRecovery = useCallback(async () => {
    if (!wallet) throw new Error("kit/native: not connected");
    const code = generateRecoveryCode();
    await wallet.setupRecovery(code);
    return code;
  }, [wallet]);

  const recover = useCallback(async (code: string) => {
    if (!identity) throw new Error("kit/native: sign in before recovery");
    const cfg = configRef.current;
    let next: CavosWallet;
    if ((cfg.chain ?? "starknet") === "solana") {
      next = await Cavos.recoverSolana({
        code,
        identity,
        network: cfg.network === "mainnet" ? "solana-mainnet" : "solana-devnet",
        appSalt: cfg.appSalt,
        appId: cfg.appId,
        environment: cfg.environment,
        backendUrl: cfg.authBackendUrl,
        rpcUrl: cfg.rpcUrl,
        minimumKeySecurity: cfg.minimumKeySecurity,
      });
    } else if (cfg.chain === "stellar") {
      next = await Cavos.connect({
        chain: "stellar", network: cfg.network, identity, appSalt: cfg.appSalt,
        appId: cfg.appId, environment: cfg.environment, backendUrl: cfg.authBackendUrl,
        minimumKeySecurity: cfg.minimumKeySecurity,
      });
      if (next.chain === "stellar" && next.status === "needs-device-approval") {
        await next.approveThisDeviceWithRecovery(code);
      }
    } else {
      next = await Cavos.recover({
        code, identity, network: cfg.network, appSalt: cfg.appSalt,
        appId: cfg.appId, environment: cfg.environment, backendUrl: cfg.authBackendUrl,
        rpcUrl: cfg.rpcUrl, paymasterApiKey: cfg.paymasterApiKey ?? "",
        minimumKeySecurity: cfg.minimumKeySecurity,
      });
    }
    setWallet(next);
    setStatus({ ...INITIAL_STATUS, isReady: true });
  }, [identity]);

  const resendDeviceApproval = useCallback(async () => {
    if (!wallet || !identity || !status.pendingRequestId) return;
    if (wallet.chain !== "starknet" && wallet.chain !== "solana") return;
    const cfg = configRef.current;
    await new HttpRecoveryClient({
      baseUrl: cfg.authBackendUrl ?? "https://cavos.xyz",
      appId: cfg.appId,
      environment: cfg.environment,
    }).requestDeviceAddition({
      userId: identity.userId,
      accountAddress: wallet.address,
      newSigner: wallet.publicKey,
      ...(identity.email ? { email: identity.email } : {}),
    });
  }, [wallet, identity, status.pendingRequestId]);

  useEffect(() => {
    if (!status.awaitingApproval || !status.pendingRequestId || !identity || !config.appId) return;
    const recovery = new HttpRecoveryClient({
      baseUrl: config.authBackendUrl ?? "https://cavos.xyz",
      appId: config.appId,
      environment: config.environment,
    });
    const requestId = status.pendingRequestId;
    let cancelled = false;
    const tick = async () => {
      try {
        const pending = await recovery.getPendingRequest(requestId);
        if (cancelled || !pending) return;
        if (pending.status === "expired") {
          setStatus((current) => ({ ...current, awaitingApproval: false, pendingRequestId: null }));
        } else if (pending.status === "approved") {
          await connect(identity);
        }
      } catch { /* retry transient failures on the next interval */ }
    };
    void tick();
    const interval = setInterval(tick, 4000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [status.awaitingApproval, status.pendingRequestId, identity, config.appId,
    config.authBackendUrl, config.environment, connect]);

  const logout = useCallback(async () => {
    await auth.clearStoredIdentity();
    setWallet(null);
    setIdentity(null);
    setStatus(INITIAL_STATUS);
    setAuthError(null);
  }, [auth]);

  const value: CavosContextValue = {
    openModal: () => setModalOpen(true), closeModal: () => setModalOpen(false),
    isAuthenticated: !!wallet, user: identity, chain: config.chain ?? "starknet",
    wallet, address: wallet?.address ?? null, walletStatus: status, capabilities,
    isLoading, authError, clearAuthError: () => setAuthError(null), login,
    sendMagicLink: (email) => auth.sendMagicLink(email), sendOtp: (email) => auth.sendOtp(email),
    verifyOtp, handleCallback, execute, signMessage, enrollPasskeyDefault,
    approveDeviceWithPasskey, setupRecovery, recover, resendDeviceApproval, logout,
  };

  return <Context.Provider value={value}>
    {children}
    {modal ? <CavosAuthModal open={modalOpen} onClose={() => setModalOpen(false)} config={modal} /> : null}
  </Context.Provider>;
}

export function useCavos(): CavosContextValue {
  const value = useContext(Context);
  if (!value) throw new Error("useCavos must be used within CavosProvider");
  return value;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "Cavos operation failed";
}
