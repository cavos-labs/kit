import { Buffer } from "buffer";

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

export function utf8(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "utf8"));
}

export function decodeUtf8(value: Uint8Array): string {
  return Buffer.from(value).toString("utf8");
}

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
