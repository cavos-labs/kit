import { readFileSync } from "fs";
import { verifyNitroAttestation } from "./attestation";

/**
 * End-to-end check against the enclave actually running in AWS: the document
 * below was produced by the deployed enclave and is verified here with the same
 * code a browser runs. It closes the loop that unit tests cannot — that what we
 * deploy is what we accept.
 */
const PCR0 = "f2f81237afb5ecd3287e622c711bef8e5fe382f13c549794e478be3f54877d0c0c80a7bc9f97150fc28150130f373f87";
const SESSION_ID = "11111111-2222-3333-4444-555555555555";

// Opt-in: this needs a live deployment. Capture a session response with
//   curl -H "x-cavos-relay-key: $SECRET" -d '{"session_id":"<uuid>"}' \
//        http://127.0.0.1:8080/sessions > /tmp/live-session.json
// on the enclave host, then run with CAVOS_LIVE_ATTESTATION=1.
const enabled = process.env.CAVOS_LIVE_ATTESTATION === "1";
const live: any = enabled ? JSON.parse(readFileSync("/tmp/live-session.json", "utf8")) : null;
const fromB64Url = (v: string) =>
  Uint8Array.from(Buffer.from(v.replace(/-/g, "+").replace(/_/g, "/"), "base64"));

(enabled ? it : it.skip)("verifies a document from the live enclave and binds it to the session", async () => {
  const attestation = await verifyNitroAttestation(
    fromB64Url(live.attestation_document_b64),
    { pcr0: PCR0 },
  );

  expect(attestation.moduleId).toContain("-enc");
  expect(Buffer.from(attestation.pcrs.get(0)!).toString("hex")).toBe(PCR0);

  // The channel key must come from inside the signed document, and must match
  // the one relayed in the clear.
  expect(attestation.publicKey).toBeDefined();
  expect(Buffer.from(attestation.publicKey!)).toEqual(
    Buffer.from(fromB64Url(live.ephemeral_public_key_b64)),
  );

  // user_data binds the document to this session and no other.
  const expected = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(SESSION_ID)),
  );
  expect(Buffer.from(attestation.userData!)).toEqual(Buffer.from(expected));
});

(enabled ? it : it.skip)("rejects the live document under any other measurement", async () => {
  await expect(
    verifyNitroAttestation(fromB64Url(live.attestation_document_b64), { pcr0: "00".repeat(48) }),
  ).rejects.toThrow(/measurement is not accepted/);
});
