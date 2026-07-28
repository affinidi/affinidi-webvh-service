/**
 * Tests for the trust-task retry policy in `lib/api.ts`.
 *
 * Two layers:
 *
 *  1. `retryDelayMs` — the SPEC §8.4 decision table, in isolation. This is
 *     where the safety rules live (which codes, which task types, how a
 *     `retryAfter` hint is honored), so it is tested exhaustively.
 *  2. `api.listAcl` end-to-end through `trustTask`, with `fetch` stubbed —
 *     proves the wrapper actually re-issues, bounds its attempts, and
 *     surfaces the original rejection when it gives up.
 *
 * `acl/list` is used for the end-to-end layer deliberately: it is not in
 * `REQUIRED_PROOF_TYPES`, so no Data Integrity proof (and therefore no
 * WebCrypto Ed25519 keypair) is needed to drive a real request through.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, retryDelayMs } from "../api";

const GRANT = "https://trusttasks.org/spec/acl/grant/0.1";
const REVOKE = "https://trusttasks.org/spec/acl/revoke/0.1";
const LIST = "https://trusttasks.org/spec/acl/list/0.1";
const SHOW = "https://trusttasks.org/spec/acl/show/0.1";
const TT_ERROR = "https://trusttasks.org/spec/trust-task-error/0.1";

const NOW = Date.parse("2026-07-28T12:00:00Z");
const at = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();

describe("retryDelayMs — SPEC §8.4 decision table", () => {
  it("never retries when the server says the error is not retryable", () => {
    // The flag is the gate: a code we would otherwise retry is still
    // refused when the server marked it terminal.
    expect(retryDelayMs(LIST, { code: "internalError", retryable: false }, NOW))
      .toBeNull();
    expect(retryDelayMs(LIST, { code: "unavailable", retryable: false }, NOW))
      .toBeNull();
  });

  it("does not retry the clock-skew proofInvalid that motivated this work", () => {
    // Post affinidi-data-integrity 0.7.8 a timestamp rejection means the
    // signer is >60s out, which re-issuing cannot fix.
    expect(retryDelayMs(GRANT, { code: "proofInvalid", retryable: false }, NOW))
      .toBeNull();
    // Even if a peer marked it retryable, it is not in the allowed set.
    expect(retryDelayMs(GRANT, { code: "proofInvalid", retryable: true }, NOW))
      .toBeNull();
  });

  it("retries `unavailable` on mutations — the task provably did not run", () => {
    for (const type of [GRANT, REVOKE]) {
      expect(retryDelayMs(type, { code: "unavailable", retryable: true }, NOW))
        .toBe(500);
    }
  });

  it("refuses `internalError` on mutations — the write may already have landed", () => {
    // This is the double-apply guard. If it ever starts returning a
    // number, a transient failure mid-grant can apply the grant twice.
    for (const type of [GRANT, REVOKE]) {
      expect(retryDelayMs(type, { code: "internalError", retryable: true }, NOW))
        .toBeNull();
    }
  });

  it("retries `internalError` on side-effect-free tasks", () => {
    for (const type of [LIST, SHOW]) {
      expect(retryDelayMs(type, { code: "internalError", retryable: true }, NOW))
        .toBe(500);
    }
  });

  it("ignores unknown codes even when flagged retryable", () => {
    expect(retryDelayMs(LIST, { code: "somethingNew", retryable: true }, NOW))
      .toBeNull();
  });

  describe("retryAfter", () => {
    const base = { code: "internalError", retryable: true } as const;

    it("retries immediately when the hint has already passed", () => {
      expect(retryDelayMs(LIST, { ...base, retryAfter: at(-5_000) }, NOW))
        .toBe(0);
    });

    it("waits out a near-future hint", () => {
      expect(retryDelayMs(LIST, { ...base, retryAfter: at(2_000) }, NOW))
        .toBe(2_000);
    });

    it("honors a hint exactly at the cap", () => {
      expect(retryDelayMs(LIST, { ...base, retryAfter: at(5_000) }, NOW))
        .toBe(5_000);
    });

    it("gives up rather than parking the user on a far-future hint", () => {
      expect(retryDelayMs(LIST, { ...base, retryAfter: at(60_000) }, NOW))
        .toBeNull();
    });

    it("gives up on an unparseable hint rather than hammering the server", () => {
      expect(retryDelayMs(LIST, { ...base, retryAfter: "not-a-date" }, NOW))
        .toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// End-to-end through trustTask, with fetch stubbed.
// ---------------------------------------------------------------------------

/** Build a `trust-task-error/0.1` response envelope. */
function errorResponse(code: string, retryable: boolean) {
  return {
    id: "urn:uuid:00000000-0000-4000-8000-000000000000",
    type: TT_ERROR,
    payload: { code, message: `${code} from test`, retryable },
  };
}

/** Build a successful `acl/list` response envelope. */
function listResponse(entries: unknown[]) {
  return {
    id: "urn:uuid:00000000-0000-4000-8000-000000000001",
    type: `${LIST}#response`,
    payload: { entries },
  };
}

/** Minimal `Response` stand-in. `request()` inspects `headers` to reject
 *  HTML fallbacks from the SPA catch-all, so the content type matters. */
const jsonOk = (body: unknown) => ({
  ok: true,
  status: 200,
  headers: new Headers({ "content-type": "application/json" }),
  json: async () => body,
  text: async () => JSON.stringify(body),
});

describe("trustTask — re-issue behaviour", () => {
  let trustTaskCalls: number;

  /**
   * Stub `fetch` so `/api/server-info` always succeeds and each
   * `/api/trust-tasks` POST returns the next queued response.
   */
  function stubFetch(responses: unknown[]) {
    trustTaskCalls = 0;
    const queue = [...responses];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: string) => {
        if (path === "/api/server-info") {
          return jsonOk({ server_did: "did:webvh:example:test", version: "0" });
        }
        if (path === "/api/trust-tasks") {
          trustTaskCalls++;
          const next = queue.shift();
          if (next === undefined) throw new Error("unexpected extra POST");
          return jsonOk(next);
        }
        throw new Error(`unexpected fetch: ${path}`);
      }),
    );
  }

  beforeEach(() => {
    // `retryAfter`-less retries pause for TRUST_TASK_DEFAULT_RETRY_DELAY_MS;
    // fake timers keep the suite instant.
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("re-issues a read-only task after a retryable internalError", async () => {
    stubFetch([
      errorResponse("internalError", true),
      listResponse([]),
    ]);

    const promise = api.listAcl();
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.entries).toEqual([]);
    expect(trustTaskCalls).toBe(2);
  });

  it("stops after one extra attempt and surfaces the original rejection", async () => {
    stubFetch([
      errorResponse("internalError", true),
      errorResponse("internalError", true),
    ]);

    const promise = api.listAcl();
    // Attach the rejection handler before advancing timers so the
    // rejection is never momentarily unhandled.
    const settled = expect(promise).rejects.toThrow(ApiError);
    await vi.runAllTimersAsync();
    await settled;

    expect(trustTaskCalls).toBe(2);
  });

  it("does not re-issue when the server marks the error terminal", async () => {
    stubFetch([errorResponse("permissionDenied", false)]);

    const promise = api.listAcl();
    const settled = expect(promise).rejects.toThrow(/permissionDenied/);
    await vi.runAllTimersAsync();
    await settled;

    expect(trustTaskCalls).toBe(1);
  });
});
