#!/usr/bin/env node
// Checks that the vault a browser is served is the vault this repository built.
//
// The vault pages hold users' keys, so what vault.cavos.xyz serves matters as
// much as what the source says. The scripts it serves are built by this
// repository's CI and published in the @cavos/kit npm package with build
// provenance. This script downloads what is live, downloads the package from
// the registry, and requires them to be byte-identical. It needs nothing but
// Node 20+, so anyone can run it:
//
//   node scripts/verify_vault.mjs
//   node scripts/verify_vault.mjs --url https://vault.cavos.xyz --version 0.6.0
//
// It detects a vault that differs from a published build. It does not prevent
// one from being served, and it only speaks for the moment it runs and the
// network it runs from.

import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";

const PACKAGE = "@cavos/kit";
const REGISTRY = "https://registry.npmjs.org";
/** How many of the newest published versions to compare against. */
const VERSIONS_TO_TRY = 10;

/** Served path -> file inside the npm tarball. */
const SCRIPTS = {
  "/vault/host.js": "package/dist/vault-browser/vault-host.global.js",
  "/vault/confirm.js": "package/dist/vault-browser/vault-confirm.global.js",
};

// The two pages are static files in cavos-web (`public/vault/`), not part of
// this package. Each loads exactly one script from its own origin. Update these
// when those files change.
const PAGES = {
  "/vault": "a252421df93f6f072afc8381e676b6b6ba626f04ad4de019f56065f24c831bf7",
  "/vault/confirm": "e9116dcdeb58c64fcb20f1f7e043ab8fe5964ae34a5e3d2e4ae84760082ca0f9",
};

// Without these a page could run a script the hashes above never see.
const REQUIRED_CSP = {
  "/vault": ["default-src 'none'", "script-src 'self'"],
  "/vault/confirm": ["default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"],
};

function argument(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Says who is asking, so the site's firewall can allow this monitor by name
// rather than have it pose as a browser.
const USER_AGENT = "cavos-vault-monitor (+https://github.com/cavos-labs/kit/blob/main/scripts/verify_vault.mjs)";

async function download(url) {
  const response = await fetch(url, {
    redirect: "follow",
    headers: { "cache-control": "no-cache", "user-agent": USER_AGENT },
  });
  if (!response.ok) {
    // A firewall refusing the monitor is not a changed vault; say which it was.
    const mitigated = response.headers.get("cf-mitigated");
    const by = mitigated ? ` (refused by the site's firewall: ${mitigated})` : "";
    throw new Error(`${url} answered ${response.status}${by}`);
  }
  return { bytes: Buffer.from(await response.arrayBuffer()), headers: response.headers };
}

/** The named files of a gzipped tar archive. Enough of ustar for an npm tarball. */
function filesFromTarball(tarball, wanted) {
  const tar = gunzipSync(tarball);
  const found = new Map();
  for (let offset = 0; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const text = (start, length) => header.subarray(start, start + length).toString("utf8").replace(/\0.*$/s, "");
    const prefix = text(345, 155);
    const name = prefix ? `${prefix}/${text(0, 100)}` : text(0, 100);
    const size = parseInt(text(124, 12).trim() || "0", 8);
    const body = offset + 512;
    if (wanted.has(name)) found.set(name, tar.subarray(body, body + size));
    offset = body + Math.ceil(size / 512) * 512;
  }
  return found;
}

async function publishedVersions(only) {
  const { bytes } = await download(`${REGISTRY}/${PACKAGE.replace("/", "%2f")}`);
  const packument = JSON.parse(bytes.toString("utf8"));
  const byNewest = Object.keys(packument.time)
    .filter((version) => packument.versions[version])
    .sort((a, b) => new Date(packument.time[b]) - new Date(packument.time[a]));
  const chosen = only ? byNewest.filter((version) => version === only) : byNewest.slice(0, VERSIONS_TO_TRY);
  if (chosen.length === 0) throw new Error(`${PACKAGE}@${only} is not on the registry`);
  return chosen.map((version) => ({
    version,
    tarball: packument.versions[version].dist.tarball,
    provenance: Boolean(packument.versions[version].dist.attestations?.provenance),
  }));
}

async function main() {
  const base = argument("url", "https://vault.cavos.xyz").replace(/\/$/, "");
  const failures = [];

  const live = {};
  for (const path of Object.keys(SCRIPTS)) live[path] = sha256((await download(base + path)).bytes);

  for (const [path, expected] of Object.entries(PAGES)) {
    const { bytes, headers } = await download(base + path);
    const actual = sha256(bytes);
    if (actual !== expected) failures.push(`${path} is not the published page (sha256 ${actual})`);
    const csp = headers.get("content-security-policy") ?? "";
    for (const directive of REQUIRED_CSP[path]) {
      if (!csp.split(";").map((part) => part.trim()).includes(directive)) {
        failures.push(`${path} is served without "${directive}" in its Content-Security-Policy`);
      }
    }
  }

  let match = null;
  for (const candidate of await publishedVersions(argument("version", null))) {
    const files = filesFromTarball((await download(candidate.tarball)).bytes, new Set(Object.values(SCRIPTS)));
    const same = Object.entries(SCRIPTS).every(([path, inTarball]) => {
      const file = files.get(inTarball);
      return file !== undefined && sha256(file) === live[path];
    });
    if (same) {
      match = candidate;
      break;
    }
  }

  for (const [path, hash] of Object.entries(live)) console.log(`${hash}  ${base}${path}`);
  if (!match) {
    failures.push(`the served scripts match no published ${PACKAGE} build among those checked`);
  } else {
    console.log(`\nThe served scripts are byte-identical to ${PACKAGE}@${match.version}.`);
    if (match.provenance) {
      console.log("That version carries npm build provenance. This script does not verify its signature;");
      console.log(`\`npm audit signatures\` in a project that installs ${PACKAGE}@${match.version} does.`);
    } else {
      failures.push(`${PACKAGE}@${match.version} was published without build provenance`);
    }
  }

  if (failures.length > 0) {
    console.error(`\nVAULT VERIFICATION FAILED for ${base}`);
    for (const failure of failures) console.error(`  - ${failure}`);
    process.exit(1);
  }
  console.log(`\nVault verified for ${base}.`);
}

main().catch((error) => {
  console.error(`VAULT VERIFICATION COULD NOT RUN: ${error.message}`);
  process.exit(2);
});
