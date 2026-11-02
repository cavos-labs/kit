import type { ConsentAction, ConsentProof } from "./consent";

export interface AccountClientOptions {
  baseUrl: string;
  appId: string;
  environment?: "development" | "production";
  /** The login's token. Read fresh on each call; these tokens expire. */
  authToken: () => string | null;
}

/** `/api/end-users/me` on the Cavos backend: the end user's own recovery switch and account deletion. */
export class AccountClient {
  constructor(private readonly opts: AccountClientOptions) {}

  async challenge(action: ConsentAction): Promise<string> {
    const { challenge } = await this.send<{ challenge: string }>("POST", "/api/end-users/me/challenge", { action });
    return challenge;
  }

  async setRecovery(enabled: boolean, challenge: string, proof: ConsentProof): Promise<"on" | "off"> {
    const { recovery } = await this.send<{ recovery: "on" | "off" }>("POST", "/api/end-users/me/recovery", {
      enabled,
      challenge,
      proof,
    });
    return recovery;
  }

  /** `proof` is null when this device holds no key; the server then deletes only if Cavos holds no recovery for the account. */
  async deleteAccount(challenge: string, proof: ConsentProof | null): Promise<void> {
    await this.send("DELETE", "/api/end-users/me", { challenge, ...(proof ? { proof } : {}) });
  }

  private async send<T>(method: "POST" | "DELETE", path: string, body: Record<string, unknown>): Promise<T> {
    const token = this.opts.authToken();
    const res = await fetch(new URL(path, this.opts.baseUrl), {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        ...body,
      }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`kit/account: ${res.status} ${text}`);
    }
    return (await res.json()) as T;
  }
}
