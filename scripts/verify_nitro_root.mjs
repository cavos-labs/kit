#!/usr/bin/env node
/**
 * Re-verify the AWS Nitro root certificate pinned in
 * `src/recovery/nitro/attestation.ts`.
 *
 * That constant is the sole trust anchor for social recovery: if it were ever
 * replaced with an attacker's root, every attestation check in the SDK would
 * pass for an enclave AWS never vouched for. This script re-derives it from
 * AWS's published download and checks two independent things:
 *
 *   1. the downloaded certificate matches the SHA-256 fingerprint AWS publishes
 *      (https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html), and
 *   2. the bytes pinned in the SDK are exactly that certificate.
 *
 * Run it before a release, and any time the pinned constant changes.
 *
 *   node scripts/verify_nitro_root.mjs
 */

import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const ROOT_URL = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip";

/** The fingerprint AWS publishes for the root certificate. */
const PUBLISHED_FINGERPRINT =
  "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B";

const here = dirname(fileURLToPath(import.meta.url));
const attestationSource = join(here, "..", "src", "recovery", "nitro", "attestation.ts");

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

/** Extract the single PEM certificate from the downloaded zip. */
async function unzipRootPem(zip) {
  // The archive holds one small entry. Shelling out to `unzip` avoids adding a
  // zip dependency for a script that runs once per release; it needs a real
  // file because the `unzip` shipped with macOS cannot read an archive from
  // stdin.
  const archive = join(tmpdir(), `nitro-root-${process.pid}.zip`);
  try {
    await writeFile(archive, zip);
    const result = spawnSync("unzip", ["-p", archive], { maxBuffer: 1 << 20 });
    if (result.status !== 0) {
      fail(`could not unzip the root certificate: ${result.stderr?.toString().trim()}`);
    }
    return result.stdout.toString("utf8");
  } finally {
    await rm(archive, { force: true });
  }
}

/** Pull the pinned base64 constant out of the TypeScript source. */
async function readPinnedCertificate() {
  const source = await readFile(attestationSource, "utf8");
  const match = source.match(
    /NITRO_ROOT_CERTIFICATE_B64\s*=\s*((?:\s*"[A-Za-z0-9+/=]*"\s*\+?)+)\s*;/,
  );
  if (!match) fail("could not find NITRO_ROOT_CERTIFICATE_B64 in attestation.ts");
  const chunks = [...match[1].matchAll(/"([A-Za-z0-9+/=]*)"/g)].map((m) => m[1]);
  return Buffer.from(chunks.join(""), "base64");
}

const response = await fetch(ROOT_URL);
if (!response.ok) fail(`downloading the root certificate returned HTTP ${response.status}`);
const pem = await unzipRootPem(Buffer.from(await response.arrayBuffer()));

const published = new X509Certificate(pem);
const publishedDer = published.raw;

const fingerprint = createHash("sha256").update(publishedDer).digest("hex").toUpperCase();
if (fingerprint !== PUBLISHED_FINGERPRINT) {
  fail(
    `the downloaded certificate does not match the fingerprint AWS publishes\n` +
      `  expected ${PUBLISHED_FINGERPRINT}\n  got      ${fingerprint}`,
  );
}

const pinned = await readPinnedCertificate();
if (!pinned.equals(publishedDer)) {
  fail("the certificate pinned in attestation.ts is not the published AWS Nitro root");
}

console.log("OK: pinned Nitro root matches AWS's published certificate");
console.log(`  subject     ${published.subject.replace(/\n/g, ", ")}`);
console.log(`  fingerprint ${fingerprint.match(/../g).join(":")}`);
console.log(`  valid until ${published.validTo}`);
