/**
 * Signing out in one tab ends the session in every tab of the origin that
 * holds it: `clearToken` announces it on a `BroadcastChannel`, and
 * `listenForSignOut` drops the copy a tab holds in memory.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearToken,
  getRefreshToken,
  getToken,
  listenForSignOut,
  resetSessionCacheForTests,
  setRefreshToken,
  setToken,
} from "../session";

const CHANNEL = "did-hosting-ui-session";

/** An unsigned JWT-shaped token carrying `session_id`. */
function tokenFor(sessionId: string): string {
  const payload = btoa(JSON.stringify({ sub: "did:example:alice", session_id: sessionId }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `e30.${payload}.sig`;
}

/** Let queued channel messages arrive. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

let stop: (() => void) | null = null;

beforeEach(() => {
  resetSessionCacheForTests();
});

afterEach(() => {
  stop?.();
  stop = null;
  resetSessionCacheForTests();
  vi.restoreAllMocks();
});

describe("sign-out across tabs", () => {
  it("another tab's sign-out of this session clears it here", async () => {
    setToken(tokenFor("s-1"));
    setRefreshToken("refresh");
    const signedOut = vi.fn();
    stop = listenForSignOut(signedOut);

    const otherTab = new BroadcastChannel(CHANNEL);
    otherTab.postMessage({ type: "signed-out", sessionId: "s-1" });
    otherTab.close();
    await settle();

    expect(getToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(signedOut).toHaveBeenCalledOnce();
  });

  it("a sign-out of a different session is ignored", async () => {
    setToken(tokenFor("s-2"));
    const signedOut = vi.fn();
    stop = listenForSignOut(signedOut);

    const otherTab = new BroadcastChannel(CHANNEL);
    otherTab.postMessage({ type: "signed-out", sessionId: "s-old" });
    otherTab.close();
    await settle();

    expect(getToken()).toBe(tokenFor("s-2"));
    expect(signedOut).not.toHaveBeenCalled();
  });

  it("clearToken announces the sign-out to other tabs", async () => {
    const received: unknown[] = [];
    const otherTab = new BroadcastChannel(CHANNEL);
    otherTab.onmessage = (e: MessageEvent) => received.push(e.data);

    setToken(tokenFor("s-3"));
    clearToken();
    await settle();
    otherTab.close();

    expect(received).toEqual([{ type: "signed-out", sessionId: "s-3" }]);
  });
});
