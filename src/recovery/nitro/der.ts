/**
 * The minimal DER / X.509 reader needed to validate a Nitro attestation
 * certificate chain in a browser.
 *
 * WebCrypto can verify an ECDSA signature but cannot parse a certificate, and
 * pulling a full X.509 stack into the SDK for four fields is not a trade worth
 * making. This reads only what chain validation actually needs: the signed
 * region, the public key, the validity window, and the CA flag.
 *
 * Everything here treats its input as hostile. Lengths are bounds-checked,
 * non-canonical DER is rejected, and any structure that does not match the
 * expected shape is an error rather than a default.
 */

const TAG_BOOLEAN = 0x01;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_CONTEXT_3 = 0xa3;

/** OID 1.2.840.10045.4.3.3 — ecdsa-with-SHA384, the only algorithm Nitro uses. */
const OID_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
/** OID 2.5.29.19 — basicConstraints. */
const OID_BASIC_CONSTRAINTS = "2.5.29.19";

export interface DerElement {
  tag: number;
  /** The full element including tag and length bytes. */
  full: Uint8Array;
  /** The element's contents, excluding tag and length bytes. */
  content: Uint8Array;
  /** Offset immediately after this element in the parent buffer. */
  end: number;
}

export interface ParsedCertificate {
  /** The exact DER bytes the signature is computed over. */
  tbs: Uint8Array;
  /** SubjectPublicKeyInfo, in the form WebCrypto's `spki` import expects. */
  subjectPublicKeyInfo: Uint8Array;
  /** Raw `r ‖ s`, converted from the DER-encoded ECDSA signature. */
  signature: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  isCertificateAuthority: boolean;
}

/** Read the DER element that starts at `offset`. */
export function readElement(bytes: Uint8Array, offset: number): DerElement {
  if (offset + 2 > bytes.length) throw new Error("der: truncated element header");
  const tag = bytes[offset];
  // Multi-byte tags would mean a structure this reader does not expect.
  if ((tag & 0x1f) === 0x1f) throw new Error("der: multi-byte tags are not supported");

  const lengthByte = bytes[offset + 1];
  let length: number;
  let headerLength: number;

  if (lengthByte < 0x80) {
    length = lengthByte;
    headerLength = 2;
  } else {
    const lengthBytes = lengthByte & 0x7f;
    if (lengthBytes === 0) throw new Error("der: indefinite lengths are not valid in DER");
    if (lengthBytes > 4) throw new Error("der: length exceeds supported range");
    if (offset + 2 + lengthBytes > bytes.length) throw new Error("der: truncated length");
    length = 0;
    for (let index = 0; index < lengthBytes; index += 1) {
      length = (length << 8) | bytes[offset + 2 + index];
    }
    // DER requires the shortest possible length encoding.
    if (length < 0x80) throw new Error("der: non-canonical length encoding");
    headerLength = 2 + lengthBytes;
  }

  const contentStart = offset + headerLength;
  const end = contentStart + length;
  if (end > bytes.length) throw new Error("der: element overruns buffer");

  return {
    tag,
    full: bytes.subarray(offset, end),
    content: bytes.subarray(contentStart, end),
    end,
  };
}

function expect(bytes: Uint8Array, offset: number, tag: number, label: string): DerElement {
  const element = readElement(bytes, offset);
  if (element.tag !== tag) {
    throw new Error(`der: expected ${label} (tag 0x${tag.toString(16)}), got 0x${element.tag.toString(16)}`);
  }
  return element;
}

/**
 * Parse an X.509 certificate far enough to validate a chain.
 *
 * The signature algorithm is checked here rather than by the caller: a chain
 * whose certificates are signed with something other than ECDSA-SHA384 is not a
 * Nitro chain, and finding that out early keeps the verifier's contract narrow.
 */
export function parseCertificate(der: Uint8Array): ParsedCertificate {
  const certificate = expect(der, 0, TAG_SEQUENCE, "Certificate");
  if (certificate.end !== der.length) throw new Error("der: trailing bytes after certificate");

  const body = certificate.content;
  const tbs = expect(body, 0, TAG_SEQUENCE, "TBSCertificate");
  const signatureAlgorithm = expect(body, tbs.end, TAG_SEQUENCE, "signatureAlgorithm");
  const signatureValue = expect(body, signatureAlgorithm.end, TAG_BIT_STRING, "signatureValue");
  if (signatureValue.end !== body.length) {
    throw new Error("der: trailing bytes after signatureValue");
  }

  const algorithmOid = readObjectIdentifier(
    expect(signatureAlgorithm.content, 0, TAG_OID, "algorithm OID"),
  );
  if (algorithmOid !== OID_ECDSA_WITH_SHA384) {
    throw new Error(`der: unexpected certificate signature algorithm ${algorithmOid}`);
  }

  // A BIT STRING's first content byte counts unused trailing bits; for a
  // signature it must be zero.
  if (signatureValue.content.length < 1 || signatureValue.content[0] !== 0) {
    throw new Error("der: malformed signature BIT STRING");
  }

  const fields = readTbsFields(tbs.content);

  return {
    tbs: tbs.full,
    subjectPublicKeyInfo: fields.subjectPublicKeyInfo,
    signature: derEcdsaSignatureToRaw(signatureValue.content.subarray(1), 48),
    issuer: fields.issuer,
    subject: fields.subject,
    notBefore: fields.notBefore,
    notAfter: fields.notAfter,
    isCertificateAuthority: fields.isCertificateAuthority,
  };
}

function readTbsFields(tbs: Uint8Array): {
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  subjectPublicKeyInfo: Uint8Array;
  isCertificateAuthority: boolean;
} {
  let offset = 0;

  // version [0] EXPLICIT, optional and defaulting to v1.
  const first = readElement(tbs, offset);
  if (first.tag === 0xa0) offset = first.end;

  const serialNumber = expect(tbs, offset, TAG_INTEGER, "serialNumber");
  const innerAlgorithm = expect(tbs, serialNumber.end, TAG_SEQUENCE, "signature");
  const issuer = expect(tbs, innerAlgorithm.end, TAG_SEQUENCE, "issuer");
  const validity = expect(tbs, issuer.end, TAG_SEQUENCE, "validity");
  const subject = expect(tbs, validity.end, TAG_SEQUENCE, "subject");
  const subjectPublicKeyInfo = expect(tbs, subject.end, TAG_SEQUENCE, "subjectPublicKeyInfo");

  const notBeforeElement = readElement(validity.content, 0);
  const notAfterElement = readElement(validity.content, notBeforeElement.end);

  return {
    issuer: issuer.full,
    subject: subject.full,
    notBefore: readTime(notBeforeElement),
    notAfter: readTime(notAfterElement),
    subjectPublicKeyInfo: subjectPublicKeyInfo.full,
    isCertificateAuthority: readCaFlag(tbs, subjectPublicKeyInfo.end),
  };
}

/**
 * Read the basicConstraints CA flag, if the certificate carries one.
 *
 * Absent basicConstraints means "not a CA" (RFC 5280), which is the safe
 * default: a chain that omits it for an issuing certificate should fail.
 */
function readCaFlag(tbs: Uint8Array, offset: number): boolean {
  let cursor = offset;
  while (cursor < tbs.length) {
    const element = readElement(tbs, cursor);
    cursor = element.end;
    if (element.tag !== TAG_CONTEXT_3) continue;

    const extensions = expect(element.content, 0, TAG_SEQUENCE, "Extensions");
    let extensionOffset = 0;
    while (extensionOffset < extensions.content.length) {
      const extension = expect(extensions.content, extensionOffset, TAG_SEQUENCE, "Extension");
      extensionOffset = extension.end;

      const oidElement = expect(extension.content, 0, TAG_OID, "extnID");
      if (readObjectIdentifier(oidElement) !== OID_BASIC_CONSTRAINTS) continue;

      // `critical` is optional and defaults to FALSE, so the OCTET STRING may
      // be either the second or the third field.
      let next = readElement(extension.content, oidElement.end);
      if (next.tag === TAG_BOOLEAN) next = readElement(extension.content, next.end);
      if (next.tag !== TAG_OCTET_STRING) throw new Error("der: malformed basicConstraints");

      const constraints = expect(next.content, 0, TAG_SEQUENCE, "BasicConstraints");
      if (constraints.content.length === 0) return false;
      const caFlag = readElement(constraints.content, 0);
      if (caFlag.tag !== TAG_BOOLEAN) return false;
      return caFlag.content.length === 1 && caFlag.content[0] !== 0;
    }
  }
  return false;
}

function readTime(element: DerElement): Date {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(element.content);

  if (element.tag === TAG_UTC_TIME) {
    // YYMMDDHHMMSSZ — RFC 5280 pivots the two-digit year at 50.
    const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!match) throw new Error("der: malformed UTCTime");
    const twoDigitYear = Number(match[1]);
    const year = twoDigitYear >= 50 ? 1900 + twoDigitYear : 2000 + twoDigitYear;
    return utc(year, match.slice(2).map(Number) as [number, number, number, number, number]);
  }

  if (element.tag === TAG_GENERALIZED_TIME) {
    // YYYYMMDDHHMMSSZ
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!match) throw new Error("der: malformed GeneralizedTime");
    return utc(
      Number(match[1]),
      match.slice(2).map(Number) as [number, number, number, number, number],
    );
  }

  throw new Error(`der: unexpected time tag 0x${element.tag.toString(16)}`);
}

function utc(
  year: number,
  [month, day, hour, minute, second]: [number, number, number, number, number],
): Date {
  return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
}

function readObjectIdentifier(element: DerElement): string {
  const content = element.content;
  if (content.length === 0) throw new Error("der: empty OID");

  const parts: number[] = [Math.floor(content[0] / 40), content[0] % 40];
  let value = 0;
  for (let index = 1; index < content.length; index += 1) {
    const byte = content[index];
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

/**
 * Convert a DER `SEQUENCE { r INTEGER, s INTEGER }` signature into the fixed
 * `r ‖ s` form WebCrypto expects. DER integers are signed and minimally
 * encoded, so they carry a leading zero when the high bit is set and drop
 * leading zero bytes otherwise; both are normalised to `size` bytes here.
 */
export function derEcdsaSignatureToRaw(der: Uint8Array, size: number): Uint8Array {
  const sequence = expect(der, 0, TAG_SEQUENCE, "ECDSA-Sig-Value");
  if (sequence.end !== der.length) throw new Error("der: trailing bytes after signature");

  const r = expect(sequence.content, 0, TAG_INTEGER, "r");
  const s = expect(sequence.content, r.end, TAG_INTEGER, "s");
  if (s.end !== sequence.content.length) throw new Error("der: unexpected signature fields");

  const out = new Uint8Array(size * 2);
  out.set(normaliseInteger(r.content, size), 0);
  out.set(normaliseInteger(s.content, size), size);
  return out;
}

function normaliseInteger(bytes: Uint8Array, size: number): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  const trimmed = bytes.subarray(start);
  if (trimmed.length > size) throw new Error("der: signature integer is too large");
  const out = new Uint8Array(size);
  out.set(trimmed, size - trimmed.length);
  return out;
}
