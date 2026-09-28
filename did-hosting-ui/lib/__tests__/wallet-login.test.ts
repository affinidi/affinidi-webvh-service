/**
 * Wallet login binds this browser's session key (`auth/authenticate/0.2`).
 *
 * The key is the real one (WebCrypto Ed25519); the wallet is a stub that
 * answers the way the extension does.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { hasSessionKeypair } from "../session-key";
import { loginBindingSessionKey, type VtaWalletLoginParams } from "../wallet-login";

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
