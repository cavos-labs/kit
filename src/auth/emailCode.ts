/** Characters in the sign-in code the enclave mails. */
export const EMAIL_CODE_LENGTH = 9;

/**
 * A code as the enclave compares it: lower-case, with whitespace and hyphens
 * removed, so a pasted `QPZ-RY9 X8G` is the code that was sent.
 */
export function normalizeEmailCode(raw: string): string {
  return raw.toLowerCase().replace(/[\s-]/g, "");
}
