/**
 * The two device-lifecycle pages every integrating app needs: approving a new
 * device, and revoking one from the "this wasn't me" link in the notification
 * email.
 *
 * They are the same flow with a different verb — resolve a request id, fetch
 * the request, mount the provider for the chain that request belongs to, make
 * the user sign in, do the on-chain change, tell the backend — so they are one
 * engine here and two thin wrappers below.
 *
 * This exists because writing it by hand has three traps, and an app only finds
 * them in production:
 *
 *   1. The sign-in step redirects through the identity provider, which returns
 *      with `?auth_data=…` and overwrites `?request=`. The id has to survive
 *      that round trip or the page loses the request the user came for.
 *   2. A signer lives on one chain. Mounting the provider for a different one
 *      asks the wrong ledger whether a key it has never seen is authorized, and
 *      the resulting "not an authorized signer" reads like the device is gone.
 *   3. The provider's config depends on the request, and the request has to be
 *      fetched before the provider exists — so the fetch cannot live in a hook
 *      under the provider.
 *
 * Rendering is deliberately unopinionated: the default markup is plain semantic
 * HTML with class names and no styles, and passing a function as `children`
 * replaces it entirely. Cavos is white-label; shipping a look would only make
 * integrators fork this file to remove it.
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import type { CavosWallet } from "../Cavos";
import type { DevicePublicKey } from "../signer/DeviceSigner";
import type { DeviceRemovalRequest, PendingDeviceRequest } from "../recovery/RecoveryClient";
import { HttpRecoveryClient } from "../recovery/HttpRecoveryClient";
import { CavosProvider, useCavos, type CavosConfig, type CavosContextValue } from "./CavosProvider";
import { configForNetwork } from "./configForNetwork";

/** What the caller can render against. */
export type DeviceFlowStatus =
  | "loading"
  | "error"
  /** The request is loaded, but nobody is signed in yet. */
  | "needs-signin"
  | "ready"
  | "submitting"
  | "done";

export interface DeviceFlowState<TRequest> {
  status: DeviceFlowStatus;
  /** Present from `needs-signin` onwards. */
  request: TRequest | null;
  error: string;
  /**
   * True when the request targets the very device being used. Revoking it would
   * strand the user on this page, so the SDK refuses — surface it before the
   * button is pressed rather than as a failure after.
   */
  isSelf: boolean;
  /** Open the sign-in modal. */
  signIn: () => void;
  /** Run the on-chain change, then confirm it to the backend. */
  submit: () => void;
}

/**
 * The four things that differ between approving and revoking. Everything else
 * is shared, so this is the whole of the variation.
 */
interface DeviceFlow<TRequest> {
  /** Distinct per flow so an approval and a revocation can be open at once. */
  stashKey: string;
  load: (client: HttpRecoveryClient, requestId: string) => Promise<TRequest | null>;
  /** The signer this flow acts on. */
  target: (request: TRequest) => DevicePublicKey;
  /** The on-chain change. Returns the transaction hash. */
  act: (cavos: CavosContextValue, target: DevicePublicKey) => Promise<{ transactionHash: string }>;
  confirm: (
    client: HttpRecoveryClient,
    request: TRequest,
    txHash: string,
    cavos: CavosContextValue,
  ) => Promise<void>;
  /** Revoking the device in use is refused; approving it is not. */
  refusesSelf: boolean;
}

export interface DeviceFlowPageProps<TRequest> {
  /**
   * The configs this app supports. The one matching the request's chain is
   * used; if it is missing, the page reports that rather than silently asking
   * the wrong chain.
   */
  configs: CavosConfig[];
  /** Cavos backend. Defaults to the hosted one. */
  backendUrl?: string;
  /** Overrides the query parameter carrying the request id. */
  paramName?: string;
  className?: string;
  /** Replace the default markup entirely. */
  children?: (state: DeviceFlowState<TRequest>) => ReactNode;
}

const DEFAULT_BACKEND = "https://cavos.xyz";

/** Approve a device that asked to join this account. */
export function ApproveDevicePage(props: DeviceFlowPageProps<PendingDeviceRequest>) {
  return (
    <DeviceFlowPage
      {...props}
      title="Approve a new device"
      flow={{
        stashKey: "cavos.approve.requestId",
        load: (client, id) => client.getPendingRequest(id),
        target: (request) => request.newSigner,
        act: (cavos, target) => cavos.addSigner(target),
        // The email is what lets the backend send the "a new device was added"
        // notice with its revocation link; the wallet row stores no address.
        confirm: (client, request, txHash, cavos) =>
          client.confirmDeviceAddition({
            requestId: request.requestId,
            txHash,
            ...(cavos.user?.email ? { email: cavos.user.email } : {}),
          }),
        refusesSelf: false,
      }}
    />
  );
}

/** Revoke a device, from the link in the "a new device was added" email. */
export function RevokeDevicePage(props: DeviceFlowPageProps<DeviceRemovalRequest>) {
  return (
    <DeviceFlowPage
      {...props}
      title="Revoke a device"
      flow={{
        stashKey: "cavos.revoke.requestId",
        load: (client, id) => client.getRemovalRequest(id),
        target: (request) => request.target,
        act: (cavos, target) => cavos.removeSigner(target),
        confirm: (client, request, txHash) =>
          client.confirmDeviceRemoval({ requestId: request.requestId, txHash }),
        refusesSelf: true,
      }}
    />
  );
}

interface EngineProps<TRequest extends { network?: string; appId?: string; status: string }>
  extends DeviceFlowPageProps<TRequest> {
  title: string;
  flow: DeviceFlow<TRequest>;
}

/**
 * Outer half: everything that has to happen before a provider can be mounted.
 */
function DeviceFlowPage<TRequest extends { network?: string; appId?: string; status: string }>({
  configs,
  backendUrl = DEFAULT_BACKEND,
  paramName = "request",
  className,
  children,
  title,
  flow,
}: EngineProps<TRequest>) {
  const requestId = useStashedRequestId(paramName, flow.stashKey);
  const [request, setRequest] = useState<TRequest | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (requestId === null) return; // still resolving
    if (!requestId) {
      setError("Missing request id.");
      setLoading(false);
      return;
    }
    const client = new HttpRecoveryClient({ baseUrl: backendUrl, appId: configs[0]?.appId ?? "" });
    flow
      .load(client, requestId)
      .then((loaded) => {
        if (!loaded) setError("Request not found.");
        else if (loaded.status === "expired") setError("This link has expired.");
        else setRequest(loaded);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
    // `flow` is a literal rebuilt every render; the request id is what changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestId, backendUrl]);

  if (loading || error || !request) {
    const state: DeviceFlowState<TRequest> = {
      status: loading ? "loading" : "error",
      request: null,
      error,
      isSelf: false,
      signIn: noop,
      submit: noop,
    };
    return children ? <>{children(state)}</> : <Shell className={className} title={title} state={state} />;
  }

  // Only now is the chain known, so only now can the provider be mounted.
  return (
    <CavosProvider config={configForNetwork(request.network, configs)}>
      <Inner
        request={request}
        flow={flow}
        backendUrl={backendUrl}
        title={title}
        className={className}
        renderChildren={children}
      />
    </CavosProvider>
  );
}

/**
 * Inner half: runs under the provider, so it can sign and read the session.
 */
function Inner<TRequest extends { network?: string; appId?: string; status: string }>({
  request,
  flow,
  backendUrl,
  title,
  className,
  renderChildren,
}: {
  request: TRequest;
  flow: DeviceFlow<TRequest>;
  backendUrl: string;
  title: string;
  className?: string;
  renderChildren?: (state: DeviceFlowState<TRequest>) => ReactNode;
}) {
  const cavos = useCavos();
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  const target = flow.target(request);
  const isSelf = flow.refusesSelf && targetsThisDevice(cavos.wallet, target);

  const submit = useCallback(async () => {
    setSubmitting(true);
    setError("");
    try {
      const { transactionHash } = await flow.act(cavos, target);
      const client = new HttpRecoveryClient({
        baseUrl: backendUrl,
        appId: request.appId ?? "",
      });
      await flow.confirm(client, request, transactionHash, cavos);
      setDone(true);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cavos, request, backendUrl]);

  const state: DeviceFlowState<TRequest> = {
    status: done
      ? "done"
      : submitting
        ? "submitting"
        : !cavos.isAuthenticated
          ? "needs-signin"
          : "ready",
    request,
    error,
    isSelf,
    signIn: cavos.openModal,
    submit,
  };

  return renderChildren ? (
    <>{renderChildren(state)}</>
  ) : (
    <Shell className={className} title={title} state={state} />
  );
}

/**
 * Deliberately plain: semantic elements and class names, no styles. Apps bring
 * their own CSS, or replace this entirely by passing a function as `children`.
 */
function Shell<TRequest>({
  className,
  title,
  state,
}: {
  className?: string;
  title: string;
  state: DeviceFlowState<TRequest>;
}) {
  return (
    <main className={className}>
      <h1>{title}</h1>
      {state.error && <p role="alert">{state.error}</p>}

      {state.status === "loading" && <p>Loading…</p>}
      {state.status === "done" && <p>Done. You can close this page.</p>}

      {state.status === "needs-signin" && (
        <button type="button" onClick={state.signIn}>
          Sign in to continue
        </button>
      )}

      {(state.status === "ready" || state.status === "submitting") &&
        (state.isSelf ? (
          <p>
            This is the device you are using. Revoke it from another device that
            still has access.
          </p>
        ) : (
          <button type="button" onClick={state.submit} disabled={state.status === "submitting"}>
            {state.status === "submitting" ? "Working…" : "Confirm"}
          </button>
        ))}
    </main>
  );
}

/**
 * Read the request id from the URL, surviving the sign-in redirect.
 *
 * Signing in leaves the page and comes back with `?auth_data=…`, which replaces
 * the query string the user arrived with. Without stashing it first, the page
 * returns from the provider having forgotten which request it was for.
 *
 * Returns `null` while resolving, `""` when there is none.
 */
function useStashedRequestId(paramName: string, stashKey: string): string | null {
  const [requestId, setRequestId] = useState<string | null>(null);
  useEffect(() => {
    const fromUrl = new URLSearchParams(window.location.search).get(paramName) || "";
    if (fromUrl) {
      sessionStorage.setItem(stashKey, fromUrl);
      setRequestId(fromUrl);
    } else {
      setRequestId(sessionStorage.getItem(stashKey) || "");
    }
  }, [paramName, stashKey]);
  return requestId;
}

/**
 * Whether a request targets the very device being used.
 *
 * Revoking it would strand the user on this page, so the SDK refuses; this is
 * what lets the page say so before the button is pressed rather than as a
 * failure after.
 *
 * Only Starknet and Solana identify a device by a P-256 key. Stellar classic
 * uses a different account model with no key to compare, so the check does not
 * apply there — and answering "no" is the safe direction: the SDK still
 * refuses, the user just does not get the early warning.
 */
export function targetsThisDevice(
  wallet: CavosWallet | null,
  target: DevicePublicKey,
): boolean {
  if (!wallet) return false;
  if (wallet.chain !== "starknet" && wallet.chain !== "solana") return false;
  return wallet.publicKey.x === target.x && wallet.publicKey.y === target.y;
}

function noop(): void {}
