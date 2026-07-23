import "react-native-get-random-values";
import { Buffer } from "buffer";

// The `buffer` npm polyfill (feross/buffer) does NOT override `subarray`, so it
// inherits Uint8Array.prototype.subarray, which returns a plain Uint8Array —
// unlike Node's Buffer, whose subarray returns a Buffer. @stellar/js-xdr's
// XdrWriter.finalize() does `this._buffer.subarray(...)`, and Transaction.toXDR()
// then calls `.toString("base64")` on the result. On a plain Uint8Array that
// yields comma-joined decimal bytes instead of base64, producing malformed XDR
// that the relayer rejects with "Invalid transaction encoding". Re-parent the
// result to Buffer.prototype so `.toString("base64")` works in React Native.
const bufferProto = Buffer.prototype as unknown as {
  subarray: (start?: number, end?: number) => Uint8Array;
  __cavosSubarrayPatched?: boolean;
};
if (!bufferProto.__cavosSubarrayPatched) {
  const originalSubarray = bufferProto.subarray;
  bufferProto.subarray = function patchedSubarray(this: Uint8Array, start?: number, end?: number) {
    const result = originalSubarray.call(this, start, end);
    Object.setPrototypeOf(result, Buffer.prototype);
    return result;
  };
  bufferProto.__cavosSubarrayPatched = true;
}

const runtime = globalThis as typeof globalThis & { Buffer?: typeof Buffer };
runtime.Buffer ??= Buffer;
