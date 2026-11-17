/**
 * What a renewal does when the control plane refuses it.
 *
 * A terminal refusal (absolute lifetime reached, idled out, revoked or
 * unknown session) ends the session once, in every tab, and nothing sends the
 * refused token again. A transient failure (the network, a 5xx, `unavailable`)
 * leaves the session alone and is retried, backing off.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SessionEndedError,
  getRefreshToken,
  getToken,
  renewIfNeeded,
  renewSessionNow,
} from "../session";
import { generateSessionKeypair } from "../session-key";
import { resetServiceInfo } from "../trust-task";
import {
  type Doc,
  type Sent,
  installControlPlane,
  rejection,
  seal,
  stubStorage,
  tokenFor,
} from "./fake-control-plane";

const REFRESH = "https://trusttasks.org/spec/auth/refresh/0.2";
const SUBJECT = "did:webvh:QmAdmin:example.com:admin";
const CHANNEL = "did-hosting-ui-session";
const T0 = Date.parse("2026-11-16T10:00:00Z");

/** An access token with `secs` left to live, so a renewal is due. */
function expiringToken(secs = 30): string {
  return tokenFor(SUBJECT, { session_id: "sess-1", exp: Math.floor(Date.now() / 1000) + secs });
}

function refreshes(sent: Sent[]): Sent[] {
  return sent.filter((s) => s.doc.type === REFRESH);
}

function renewed(req: Doc): Doc {
  return seal(req, {
    tokens: {
      accessToken: tokenFor(SUBJECT, {
        session_id: "sess-1",
        exp: Math.floor(Date.now() / 1000) + 900,
      }),
      refreshToken: "refresh-2",
      tokenType: "Bearer",
      expiresIn: 900,
    },
  });
}

/** Let queued channel messages arrive. */
async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 20));
}

let unauthorized: ReturnType<typeof vi.fn<() => void>>;
let otherTab: BroadcastChannel;
let broadcasts: unknown[];

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  resetServiceInfo();
  stubStorage({
    webvh_token: expiringToken(),
    webvh_refresh_token: "refresh-1",
    webvh_auth_method: "passkey",
  });
  await generateSessionKeypair();
  unauthorized = vi.fn<() => void>();
  // The node test environment has no `window`; the session module only
  // dispatches its "session expired" event on one.
  vi.stubGlobal("window", new EventTarget());
  window.addEventListener("webvh:unauthorized", unauthorized);
  broadcasts = [];
  otherTab = new BroadcastChannel(CHANNEL);
  otherTab.onmessage = (e: MessageEvent) => broadcasts.push(e.data);
});

afterEach(() => {
  window.removeEventListener("webvh:unauthorized", unauthorized);
  otherTab.close();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("a terminal refresh refusal", () => {
  it.each([
    ["an idled-out or unknown session", "permissionDenied"],
    ["the absolute lifetime", "auth/refresh:sessionLifetimeExceeded"],
    ["a revoked token", "auth/refresh:tokenRevoked"],
  ])("for %s ends the session once and is never retried", async (_, code) => {
    const sent = installControlPlane((req) =>
      req.type === REFRESH ? rejection(code, false) : undefined,
    );

    await renewIfNeeded();

    expect(refreshes(sent)).toHaveLength(1);
    expect(getToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(unauthorized).toHaveBeenCalledOnce();

    // The other tabs holding the session are told, so they stop too.
    await settle();
    expect(broadcasts).toEqual([{ type: "signed-out", sessionId: "sess-1" }]);

    // However long the page stays open and however often it polls, the
    // refused token is not sent again.
    for (let i = 0; i < 10; i++) {
      vi.setSystemTime(Date.now() + 60_000);
      await renewIfNeeded();
    }
    expect(refreshes(sent)).toHaveLength(1);
    expect(unauthorized).toHaveBeenCalledOnce();
  });

  it("ends the session when a step-up's renewal is refused, too", async () => {
    installControlPlane((req) =>
      req.type === REFRESH ? rejection("auth/refresh:sessionLifetimeExceeded") : undefined,
    );

    await expect(renewSessionNow()).rejects.toBeInstanceOf(SessionEndedError);
    expect(getToken()).toBeNull();
    expect(unauthorized).toHaveBeenCalledOnce();
  });
});

describe("a transient refresh failure", () => {
  it("keeps the session and retries, backing off", async () => {
    let fail = true;
    const sent = installControlPlane((req) => {
      if (req.type !== REFRESH) return undefined;
      return fail ? rejection("unavailable", true) : renewed(req);
    });
    const before = getToken();

    await renewIfNeeded();
    // The Trust Task client re-issues an `unavailable` once on its own.
    const afterFirst = refreshes(sent).length;
    expect(afterFirst).toBeGreaterThanOrEqual(1);
    expect(getToken()).toBe(before);
    expect(unauthorized).not.toHaveBeenCalled();

    // Inside the backoff window: nothing is sent.
    vi.setSystemTime(Date.now() + 4_000);
    await renewIfNeeded();
    expect(refreshes(sent)).toHaveLength(afterFirst);

    // Past it: retried, and a second failure doubles the wait.
    vi.setSystemTime(Date.now() + 2_000);
    await renewIfNeeded();
    const afterSecond = refreshes(sent).length;
    expect(afterSecond).toBeGreaterThan(afterFirst);
    vi.setSystemTime(Date.now() + 6_000);
    await renewIfNeeded();
    expect(refreshes(sent)).toHaveLength(afterSecond);

    // The service is back: the retry renews the session.
    fail = false;
    vi.setSystemTime(Date.now() + 5_000);
    await renewIfNeeded();
    expect(getRefreshToken()).toBe("refresh-2");
    expect(getToken()).not.toBe(before);
    expect(unauthorized).not.toHaveBeenCalled();
  });

  it("treats a network failure as transient", async () => {
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        calls += 1;
        throw new TypeError("Failed to fetch");
      }),
    );

    await renewIfNeeded();
    expect(calls).toBeGreaterThanOrEqual(1);
    expect(getRefreshToken()).toBe("refresh-1");
    expect(unauthorized).not.toHaveBeenCalled();

    const before = calls;
    vi.setSystemTime(Date.now() + 6_000);
    await renewIfNeeded();
    expect(calls).toBeGreaterThan(before);
    expect(getRefreshToken()).toBe("refresh-1");
  });
});
