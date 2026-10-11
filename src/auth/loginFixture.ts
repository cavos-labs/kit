import type { CavosAuth } from "./CavosAuth";

/** The app the fixture's "backend" prefixes onto the nonce. */
export const FIXTURE_APP_ID = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";

/**
 * Test fixture: run the first half of a Google or Apple login and return the
 * `nonce` the provider would sign, as the Cavos backend forwards it.
 *
 * A token the kit accepts has to answer a login the kit started, so tests that
 * hand it a Google or Apple token begin one here instead of inventing a nonce.
 */
export async function beginLogin(auth: CavosAuth): Promise<string> {
  const scope = globalThis as { window?: unknown };
  if (typeof scope.window === "undefined") scope.window = {};
  const realFetch = globalThis.fetch;
  let requested = "";
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    requested = String(input);
    return { ok: true, json: async () => ({ url: "https://provider.test/authorize" }) } as Response;
  }) as typeof fetch;
  try {
    await auth.getGoogleOAuthUrl("https://app.test/callback");
  } finally {
    globalThis.fetch = realFetch;
  }
  return `${FIXTURE_APP_ID}.${new URL(requested).searchParams.get("nonce")}`;
}
