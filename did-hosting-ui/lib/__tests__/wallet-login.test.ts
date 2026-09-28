/**
 * Wallet login binds this browser's session key (`auth/authenticate/0.2`).
 *
 * The key is the real one (WebCrypto Ed25519); the wallet is a stub that
 * answers the way the extension does.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { hasSessionKeypair, signEnvelope } from "../session-key";
import {
  authenticateIdTokenBindingSessionKey,
  loginBindingSessionKey,
  type VtaWalletLoginParams,
} from "../wallet-login";

const PARAMS = { rpDid: "did:webvh:QmRp:example.com", baseUrl: "https://console.example.com/api" };
const TOKENS = { accessToken: "AT", refreshToken: "RT", sessionId: "sess-1", holderDid: "did:peer:2.holder" };

afterEach(() => {
  vi.restoreAllMocks();
});

describe("wallet login", () => {
  it("asks the wallet to bind a fresh non-extractable did:key and keeps it", async () => {
    let asked: VtaWalletLoginParams | undefined;
    const wallet = {
      login: vi.fn(async (p: VtaWalletLoginParams) => {
        asked = p;
        return { ...TOKENS, sessionKey: p.sessionKey };
      }),
    };

    const result = await loginBindingSessionKey(wallet, PARAMS);

    expect(asked).toMatchObject(PARAMS);
    expect(asked!.sessionKey).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    expect(result.sessionKey).toBe(asked!.sessionKey);
    expect(hasSessionKeypair()).toBe(true);
  });

  it("uses a new key for every login", async () => {
    const keys: string[] = [];
    const wallet = {
      login: async (p: VtaWalletLoginParams) => {
        keys.push(p.sessionKey!);
        return { ...TOKENS, sessionKey: p.sessionKey };
      },
    };
    await loginBindingSessionKey(wallet, PARAMS);
    await loginBindingSessionKey(wallet, PARAMS);
    expect(keys[0]).not.toBe(keys[1]);
  });

  it("fails, and drops the key, when the wallet signs in without binding it", async () => {
    const wallet = { login: async () => ({ ...TOKENS }) };
    await expect(loginBindingSessionKey(wallet, PARAMS)).rejects.toThrow(/without binding/);
    expect(hasSessionKeypair()).toBe(false);
  });

  it("drops the key when the login is refused", async () => {
    const wallet = {
      login: async () => {
        throw new Error("login denied by user");
      },
    };
    await expect(loginBindingSessionKey(wallet, PARAMS)).rejects.toThrow(/denied/);
    expect(hasSessionKeypair()).toBe(false);
  });
});

describe("wallet proxy login", () => {
  const API = "https://console.example.com/api";
  const ARGS = {
    idToken: "h.p.s",
    sessionId: "sess-1",
    typeUri: "https://trusttasks.org/spec/auth/authenticate/0.1",
  };
  const OK = {
    session: { id: "sess-1", subject: "did:webvh:QmP:example.com:persona", issuedAt: "", expiresAt: "" },
    tokens: { accessToken: "AT", refreshToken: "RT", tokenType: "Bearer", expiresIn: 900 },
  };

  it("binds a fresh session key beside the id_token and keeps it", async () => {
    // Without a bound key every call went through the wallet's
    // `signTrustTask`, which prompts each time: one popup per request.
    let sent: Record<string, any> | undefined;
    const fetchFn = vi.fn(async (_url: string, init: RequestInit) => {
      sent = JSON.parse(init.body as string);
      return new Response(JSON.stringify(OK), { status: 200 });
    }) as unknown as typeof fetch;

    const { response } = await authenticateIdTokenBindingSessionKey(API, ARGS, fetchFn);

    expect(fetchFn).toHaveBeenCalledWith(`${API}/auth/`, expect.anything());
    expect(sent!.payload).toMatchObject({ id_token: "h.p.s", session_id: "sess-1" });
    const pk = sent!.payload.session_pubkey_b58btc as string;
    expect(pk).toMatch(/^z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    // The key held is the one bound, so `trust-task.ts` signs with it.
    const signed = await signEnvelope<{ type: string; proof?: unknown }>({ type: "t" });
    expect((signed.proof as { verificationMethod: string }).verificationMethod).toBe(
      `did:key:${pk}#${pk}`,
    );
    expect(response.tokens.accessToken).toBe("AT");
  });

  it("drops the key when the control plane refuses the login", async () => {
    const fetchFn = (async () =>
      new Response("id_token has expired", { status: 401 })) as unknown as typeof fetch;
    await expect(authenticateIdTokenBindingSessionKey(API, ARGS, fetchFn)).rejects.toThrow(
      /\/auth\/ failed \(401\)/,
    );
    expect(hasSessionKeypair()).toBe(false);
  });

  it("drops the key when the reply carries no token", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ session: OK.session }), { status: 200 })) as unknown as typeof fetch;
    await expect(authenticateIdTokenBindingSessionKey(API, ARGS, fetchFn)).rejects.toThrow(
      /missing tokens\.accessToken/,
    );
    expect(hasSessionKeypair()).toBe(false);
  });

  it("drops the key when the request never arrives", async () => {
    const fetchFn = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    await expect(authenticateIdTokenBindingSessionKey(API, ARGS, fetchFn)).rejects.toThrow(
      /Failed to fetch/,
    );
    expect(hasSessionKeypair()).toBe(false);
  });
});
