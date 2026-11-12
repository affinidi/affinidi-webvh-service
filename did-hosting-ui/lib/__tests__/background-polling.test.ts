/**
 * Timer-driven reads are marked as background requests, so the control plane
 * does not count them as activity and an unattended console still reaches its
 * idle sign-out; and a poll stays quiet while the page is hidden.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, resetServiceInfo } from "../api";
import { startPolling, type PollEnvironment } from "../poll";
import { generateSessionKeypair } from "../session-key";
import {
  SERVER_INFO,
  installControlPlane,
  rejection,
  stubStorage,
  tokenFor,
  type Sent,
} from "./fake-control-plane";

const SUBJECT = "did:webvh:QmAdmin:example.com:admin";
const TOKEN = tokenFor(SUBJECT, { session_id: "sess-1" });

const tasks = (sent: Sent[]) => sent.filter((s) => s.doc.type !== SERVER_INFO);

beforeEach(async () => {
  resetServiceInfo();
  stubStorage({ webvh_token: TOKEN, webvh_auth_method: "passkey" });
  await generateSessionKeypair();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("background requests", () => {
  // The replies do not matter here, only how the requests were sent, so the
  // fake refuses every task.
  const refuseAll = () => installControlPlane(() => rejection("notFound"));

  it("marks every read of a background dashboard refresh", async () => {
    const sent = refuseAll();
    await api.getServicesOverview({ background: true }).catch(() => undefined);

    // `Promise.all` settles on the first refusal; the other reads are still
    // on their way out.
    await vi.waitFor(() => expect(tasks(sent)).toHaveLength(3));
    const sentTasks = tasks(sent);
    for (const s of sentTasks) {
      expect(s.background, s.doc.type).toBe(true);
      expect(s.bearer).toBe(`Bearer ${TOKEN}`);
    }
  });

  it("does not mark the same reads when the operator asks for them", async () => {
    const sent = refuseAll();
    await api.getServicesOverview().catch(() => undefined);

    // `Promise.all` settles on the first refusal; the other reads are still
    // on their way out.
    await vi.waitFor(() => expect(tasks(sent)).toHaveLength(3));
    const sentTasks = tasks(sent);
    for (const s of sentTasks) expect(s.background, s.doc.type).toBe(false);
  });

  it("marks a background log poll", async () => {
    const sent = refuseAll();
    await api.getDidLog("abc", { background: true }).catch(() => undefined);
    await api.getDidLog("abc").catch(() => undefined);

    expect(tasks(sent).map((s) => s.background)).toEqual([true, false]);
  });

  it("marks the reads a poll triggers: agent names, DID detail and stats", async () => {
    const sent = refuseAll();
    await api.resolveAgentNames(["did:example:a"], { background: true }).catch(() => undefined);
    await api.getStats("abc", { background: true }).catch(() => undefined);
    await api.getDid("abc", { background: true }).catch(() => undefined);
    await vi.waitFor(() => expect(tasks(sent)).toHaveLength(4));
    for (const s of tasks(sent)) expect(s.background, s.doc.type).toBe(true);

    const before = tasks(sent).length;
    await api.resolveAgentNames(["did:example:a"]).catch(() => undefined);
    await api.getStats("abc").catch(() => undefined);
    expect(tasks(sent).slice(before).map((s) => s.background)).toEqual([false, false]);
  });
});

/** A poll environment the test drives by hand. */
function fakeEnvironment() {
  let hidden = false;
  let timer: (() => void) | null = null;
  let visibility: (() => void) | null = null;
  const env: PollEnvironment = {
    isHidden: () => hidden,
    onVisibilityChange: (listener) => {
      visibility = listener;
      return () => {
        visibility = null;
      };
    },
    setInterval: (fn) => {
      timer = fn;
      return 1;
    },
    clearInterval: () => {
      timer = null;
    },
  };
  return {
    env,
    tick: () => timer?.(),
    setHidden: (h: boolean) => {
      hidden = h;
      visibility?.();
    },
    get running() {
      return timer !== null || visibility !== null;
    },
  };
}

describe("startPolling", () => {
  it("does not fire at start, and fires each tick as a background request", () => {
    const fake = fakeEnvironment();
    const ticks: boolean[] = [];
    startPolling((t) => ticks.push(t.background), 5000, fake.env);

    expect(ticks).toEqual([]);
    fake.tick();
    fake.tick();
    expect(ticks).toEqual([true, true]);
  });

  it("skips ticks while the page is hidden and refreshes once when it is shown", () => {
    const fake = fakeEnvironment();
    let count = 0;
    startPolling(() => count++, 5000, fake.env);

    fake.setHidden(true);
    fake.tick();
    fake.tick();
    expect(count).toBe(0);

    fake.setHidden(false);
    expect(count).toBe(1);
    fake.tick();
    expect(count).toBe(2);
  });

  it("stops the timer and the visibility listener", () => {
    const fake = fakeEnvironment();
    let count = 0;
    const stop = startPolling(() => count++, 5000, fake.env);
    stop();

    expect(fake.running).toBe(false);
    fake.tick();
    fake.setHidden(false);
    expect(count).toBe(0);
  });
});
