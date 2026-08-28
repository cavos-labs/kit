import { describe, expect, it } from "@jest/globals";
import {
  shouldSkipSilentReconnect,
  urlHasOAuthCallbackCode,
} from "./oauthCallback";

/**
 * The race that produced `registry lookup failed: 401` on the demo:
 * replaceState removes `cavos_auth_code`, then silent reconnect restores the
 * previous localStorage identity in the same tick and looks up without a token.
 */
describe("shouldSkipSilentReconnect", () => {
  it("skips when the OAuth callback has already claimed this mount", () => {
    expect(
      shouldSkipSilentReconnect({
        oauthCallbackInFlight: true,
        urlHasAuthCode: false,
      }),
    ).toBe(true);
  });

  it("skips while the URL still carries the one-time code", () => {
    expect(
      shouldSkipSilentReconnect({
        oauthCallbackInFlight: false,
        urlHasAuthCode: true,
      }),
    ).toBe(true);
  });

  it("reconnects when neither is true", () => {
    expect(
      shouldSkipSilentReconnect({
        oauthCallbackInFlight: false,
        urlHasAuthCode: false,
      }),
    ).toBe(false);
  });
});

describe("urlHasOAuthCallbackCode", () => {
  it("detects cavos_auth_code", () => {
    expect(urlHasOAuthCallbackCode("?cavos_auth_code=abc")).toBe(true);
  });

  it("detects legacy auth_data and zk_auth_data", () => {
    expect(urlHasOAuthCallbackCode("?auth_data=xyz")).toBe(true);
    expect(urlHasOAuthCallbackCode("?zk_auth_data=xyz")).toBe(true);
  });

  it("is false for an ordinary URL", () => {
    expect(urlHasOAuthCallbackCode("?foo=1")).toBe(false);
    expect(urlHasOAuthCallbackCode("")).toBe(false);
  });
});
