/**
 * Nothing secret may live in `localStorage`: the access token, the refresh
 * token and the session keypair are all bearer-equivalent — anything that
 * can read one can act as the signed-in subject. `localStorage` is a flat,
 * synchronous, enumerable object (`Object.entries(localStorage)`), which is
 * exactly what a generic exfiltration payload greps first. These tests pin
 * `session.ts`'s in-memory-cache-plus-IndexedDB design (see its module doc)
 * by proving `localStorage` is never touched by any of it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearToken,
  getAuthMethod,
  getRefreshToken,
  getToken,
  resetSessionCacheForTests,
  setAuthMethod,
  setRefreshToken,
  setToken,
} from "../session";

type Call = { method: "getItem" | "setItem" | "removeItem"; key: string; value?: string };

let calls: Call[];

function stubLocalStorage(): void {
  calls = [];
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => {
      calls.push({ method: "getItem", key });
      return null;
    },
    setItem: (key: string, value: string) => {
      calls.push({ method: "setItem", key, value });
    },
    removeItem: (key: string) => {
      calls.push({ method: "removeItem", key });
    },
  });
}

beforeEach(() => {
  resetSessionCacheForTests();
  stubLocalStorage();
});

afterEach(() => {
  vi.unstubAllGlobals();
  resetSessionCacheForTests();
});

describe("session token storage", () => {
  it("setToken/setRefreshToken/setAuthMethod never touch localStorage", () => {
    setToken("secret-access-token");
    setRefreshToken("secret-refresh-token");
    setAuthMethod("wallet");

    expect(getToken()).toBe("secret-access-token");
    expect(getRefreshToken()).toBe("secret-refresh-token");
    expect(getAuthMethod()).toBe("wallet");
    expect(calls).toHaveLength(0);
  });

  it("getToken/getRefreshToken/getAuthMethod never read localStorage", () => {
    setToken("secret-access-token");
    setRefreshToken("secret-refresh-token");
    setAuthMethod("passkey");
    calls.length = 0; // only the reads below count

    getToken();
    getRefreshToken();
    getAuthMethod();

    expect(calls).toHaveLength(0);
  });

  it("clearToken (logout) clears the in-memory cache and never touches localStorage", () => {
    setToken("secret-access-token");
    setRefreshToken("secret-refresh-token");
    setAuthMethod("wallet");

    clearToken();

    expect(getToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(getAuthMethod()).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("no secret value is ever handed to localStorage.setItem, even alongside a legitimate write", () => {
    setToken("secret-access-token");
    setRefreshToken("secret-refresh-token");
    // Simulate the app's own, unrelated localStorage use (a UI preference) —
    // this must not carry a token along with it.
    localStorage.setItem("didhosting:proxyLoginViz", "1");

    const written = calls.filter((c) => c.method === "setItem").map((c) => c.value);
    expect(written).toEqual(["1"]);
    expect(written).not.toContain("secret-access-token");
    expect(written).not.toContain("secret-refresh-token");
  });
});
