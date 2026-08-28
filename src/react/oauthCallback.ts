/**
 * After OAuth lands, CavosProvider strips `cavos_auth_code` from the URL and
 * then the silent-reconnect effect runs in the same tick. By then the URL is
 * clean, so reconnect restores the old localStorage identity and the registry
 * lookup runs with no Bearer token — `GET /api/wallets` answers 401.
 *
 * Mark the callback in flight *before* `replaceState` cleans the URL, and skip
 * silent reconnect while that mark is set.
 */

export function urlHasOAuthCallbackCode(search: string): boolean {
  const params = new URLSearchParams(
    search.startsWith("?") ? search.slice(1) : search,
  );
  return !!(
    params.get("cavos_auth_code") ||
    params.get("auth_data") ||
    params.get("zk_auth_data")
  );
}

/**
 * Whether the silent-reconnect effect should stay out of the way of an OAuth
 * callback that is already being handled on this mount.
 */
export function shouldSkipSilentReconnect(opts: {
  /** Set true before the URL is cleaned of the one-time auth code. */
  oauthCallbackInFlight: boolean;
  /** True when the address bar still carries a callback code. */
  urlHasAuthCode: boolean;
}): boolean {
  return opts.oauthCallbackInFlight || opts.urlHasAuthCode;
}
