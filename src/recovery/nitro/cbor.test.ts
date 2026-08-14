import { decodeCbor, encodeSigStructure, type CborTagged } from "./cbor";

const bytes = (...values: number[]) => Uint8Array.from(values);

describe("decodeCbor", () => {
  it("decodes the indefinite-length maps that real Nitro documents use", () => {
    // bf 61 61 01 61 62 02 ff  ->  {"a": 1, "b": 2}
    const value = decodeCbor(bytes(0xbf, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02, 0xff));
    expect(value).toBeInstanceOf(Map);
    expect((value as Map<string, number>).get("a")).toBe(1);
    expect((value as Map<string, number>).get("b")).toBe(2);
  });

  it("decodes indefinite-length arrays", () => {
    // 9f 01 02 ff  ->  [1, 2]
    expect(decodeCbor(bytes(0x9f, 0x01, 0x02, 0xff))).toEqual([1, 2]);
  });

  it("decodes nested indefinite containers", () => {
    // bf 61 61 9f 01 ff ff  ->  {"a": [1]}
    const value = decodeCbor(bytes(0xbf, 0x61, 0x61, 0x9f, 0x01, 0xff, 0xff));
    expect((value as Map<string, unknown>).get("a")).toEqual([1]);
  });

  it("decodes CBOR null, which marks absent optional fields", () => {
    expect(decodeCbor(bytes(0xf6))).toBeNull();
  });

  it("reads a tagged value", () => {
    // d2 01 -> tag(18) 1. Tags below 24 are inlined in the initial byte; the
    // two-byte form (d8 12) is non-canonical and rejected. Real Nitro documents
    // are untagged, so this path is belt-and-braces for other COSE producers.
    const tagged = decodeCbor(bytes(0xd2, 0x01)) as CborTagged;
    expect(tagged.tag).toBe(18);
    expect(tagged.value).toBe(1);
  });

  it("rejects a non-canonical tag encoding", () => {
    expect(() => decodeCbor(bytes(0xd8, 0x12, 0x01))).toThrow(/non-canonical/);
  });

  it("rejects an unterminated indefinite container", () => {
    expect(() => decodeCbor(bytes(0xbf, 0x61, 0x61, 0x01))).toThrow(/unterminated/);
  });

  it("rejects an indefinite map whose final key has no value", () => {
    expect(() => decodeCbor(bytes(0xbf, 0x61, 0x61, 0xff))).toThrow(/key without a value/);
  });

  it("rejects chunked strings, which the NSM does not emit", () => {
    // 5f ... ff — indefinite-length byte string
    expect(() => decodeCbor(bytes(0x5f, 0x41, 0x01, 0xff))).toThrow(/major type 2/);
  });

  it("rejects a stray break code", () => {
    expect(() => decodeCbor(bytes(0xff))).toThrow(/major type 7/);
  });

  it("rejects duplicate map keys in both map encodings", () => {
    // Definite-length: a2 61 61 01 61 61 02
    expect(() => decodeCbor(bytes(0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02))).toThrow(/duplicate/);
    // Indefinite-length: bf 61 61 01 61 61 02 ff
    expect(() => decodeCbor(bytes(0xbf, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02, 0xff))).toThrow(
      /duplicate/,
    );
  });

  it("rejects non-canonical integer widths", () => {
    // 18 01 encodes 1 in a byte that should have been inlined.
    expect(() => decodeCbor(bytes(0x18, 0x01))).toThrow(/non-canonical/);
    // 19 00 01 encodes 1 in two bytes.
    expect(() => decodeCbor(bytes(0x19, 0x00, 0x01))).toThrow(/non-canonical/);
  });

  it("rejects trailing bytes after the top-level item", () => {
    expect(() => decodeCbor(bytes(0x01, 0x01))).toThrow(/trailing bytes/);
  });

  it("rejects a truncated item", () => {
    expect(() => decodeCbor(bytes(0x42, 0x01))).toThrow(/unexpected end of input/);
  });
});

describe("encodeSigStructure", () => {
  it("builds the COSE Signature1 array", () => {
    const encoded = encodeSigStructure(bytes(0xa1), bytes(), bytes(0x01, 0x02));
    // 84                      array(4)
    // 6a 5369676e617475726531 "Signature1"
    // 41 a1                   bstr(1) protected
    // 40                      bstr(0) external_aad
    // 42 0102                 bstr(2) payload
    expect(Buffer.from(encoded).toString("hex")).toBe(
      "846a5369676e6174757265314" + "1a1" + "40" + "420102",
    );
  });

  it("encodes lengths that need a 1- and 2-byte header", () => {
    const medium = encodeSigStructure(new Uint8Array(30), new Uint8Array(0), new Uint8Array(0));
    // bstr(30) is encoded as 58 1e
    expect(Buffer.from(medium).toString("hex")).toContain("581e");

    const large = encodeSigStructure(new Uint8Array(0), new Uint8Array(0), new Uint8Array(4374));
    // bstr(4374) is encoded as 59 1116 — the width real documents use.
    expect(Buffer.from(large).toString("hex")).toContain("591116");
  });
});
