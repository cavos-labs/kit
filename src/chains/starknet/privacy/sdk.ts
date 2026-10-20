export type PrivacySdk = typeof import("@starkware-libs/starknet-privacy-sdk");

let loaded: Promise<PrivacySdk> | undefined;

/** The privacy SDK is an optional peer dependency, loaded the first time a private operation needs it. */
export function loadPrivacySdk(): Promise<PrivacySdk> {
  loaded ??= import("@starkware-libs/starknet-privacy-sdk").catch((error: unknown) => {
    loaded = undefined;
    const detail = error instanceof Error && error.message ? ` Original error: ${error.message}` : "";
    throw new Error(
      'kit/starknet: private transfers need the optional peer dependency "@starkware-libs/starknet-privacy-sdk". ' +
        "It is published to GitHub Packages, not npmjs: point the @starkware-libs scope at https://npm.pkg.github.com " +
        `with a token that has read:packages, then install it. Requires Node 24 or newer.${detail}`,
    );
  });
  return loaded;
}
