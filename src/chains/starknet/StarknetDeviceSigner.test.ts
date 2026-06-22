import { StarknetDeviceSigner } from "./StarknetDeviceSigner";
import type { DeviceSigner, DevicePublicKey, DeviceSignature } from "../../signer/DeviceSigner";

const PUB: DevicePublicKey = {
  x: 0x9a60dea803efe2c5ac2332f021401b1d344a8381a2727c2a82a5755a207cf0ffn,
  y: 0x523f353cabeaf050e718ed1c296943ce49652d15af2c6d87cab25adf8caf210n,
};
const R = 0x7a284f75aaf1ffe510f65907503cde84bca66e7386672e42c60f027474b41ab3n;
const S = 0xa8615337502fda4c6c294814e7857174d04fdfd77fe60882fdb5b4c4226c6062n;

// Returns a fixed signature; records the txHash width it was asked to sign.
class FakeDeviceSigner implements DeviceSigner {
  lastTxHashLen = 0;
  async getPublicKey() {
    return PUB;
  }
  async sign(txHash: Uint8Array): Promise<DeviceSignature> {
    this.lastTxHashLen = txHash.length;
    return { r: R, s: S, yParity: true };
  }
}

describe("StarknetDeviceSigner", () => {
  it("serializes the device signature into a 5-felt hex signature", async () => {
    const device = new FakeDeviceSigner();
    const signer = new StarknetDeviceSigner(device);
    const sig = await (signer as unknown as {
      signRaw(h: string): Promise<string[]>;
    }).signRaw("0x012a3f4b262b7bc46495e36741af81bca4add460445d1f38f5d5cdc67e65f6ba");

    expect(sig).toHaveLength(5);
    expect(sig[0]).toBe("0xbca66e7386672e42c60f027474b41ab3"); // r_low
    expect(sig[4]).toBe("0x1"); // y_parity
    expect(device.lastTxHashLen).toBe(32); // signs the 32-byte tx hash
  });

  it("reports no single Stark pubkey", async () => {
    const signer = new StarknetDeviceSigner(new FakeDeviceSigner());
    expect(await signer.getPubKey()).toBe("0x0");
  });
});
