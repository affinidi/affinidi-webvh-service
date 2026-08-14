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

import { ApiError, TrustTaskRejection, api, retryDelayMs } from "../api";

const GRANT = "https://trusttasks.org/spec/acl/grant/0.1";
const REVOKE = "https://trusttasks.org/spec/acl/revoke/0.1";
const CHANGE_ROLE = "https://trusttasks.org/spec/acl/change-role/0.1";
const LIST = "https://trusttasks.org/spec/acl/list/0.1";
const SHOW = "https://trusttasks.org/spec/acl/show/0.1";
// The version the control plane actually emits. `trust-tasks-rs` has emitted
// `trust-task-error/0.3` since its 0.3 release and the workspace is on 0.4.1.
// This file used to say `0.1`, which nothing has sent for some time — one half
// of why the rejection path could be broken in production and green here.
const TT_ERROR = "https://trusttasks.org/spec/trust-task-error/0.3";

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

  it("retries `unavailable` on any mutation — the task provably did not run", () => {
    for (const type of [GRANT, REVOKE, CHANGE_ROLE]) {
      expect(retryDelayMs(type, { code: "unavailable", retryable: true }, NOW))
        .toBe(500);
    }
  });

  it("retries `internalError` where re-applying is a no-op", () => {
    // Reads have nothing to duplicate; `acl/grant` is idempotent by
    // SPEC §3 ("re-emitting an identical grant produces no state
    // change"), so a re-issue after a silent success changes nothing.
    for (const type of [LIST, SHOW, GRANT]) {
      expect(retryDelayMs(type, { code: "internalError", retryable: true }, NOW))
        .toBe(500);
    }
  });

  it("refuses `internalError` where a re-issue would report a misleading error", () => {
    // Neither corrupts state — both fail cleanly — but a re-issue after
    // a first attempt that silently succeeded reports failure for an
    // operation that worked: `subject_not_present` for revoke,
    // `state_mismatch` for the state-checked change-role.
    for (const type of [REVOKE, CHANGE_ROLE]) {
      expect(retryDelayMs(type, { code: "internalError", retryable: true }, NOW))
        .toBeNull();
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

/** The part of `Response` that `request()` actually touches. Named so the
 *  stand-ins below can be annotated — without a declared return type, `text`
 *  referring to a value the same object literal computes is circular (TS7023). */
interface StubResponse {
  ok: boolean;
  status: number;
  statusText?: string;
  headers: Headers;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}

/** Minimal `Response` stand-in. `request()` inspects `headers` to reject
 *  HTML fallbacks from the SPA catch-all, so the content type matters. */
const jsonOk = (body: unknown): StubResponse => ({
  ok: true,
  status: 200,
  headers: new Headers({ "content-type": "application/json" }),
  json: async () => body,
  text: async () => JSON.stringify(body),
});

/**
 * A rejection as the control plane actually returns one: the error document at
 * the status `status_for_code` maps its framework code to — never 200.
 *
 * Serving these at 200 (which this file did) is the other half of why the
 * rejection path was green here and dead in production: `request()` throws on
 * the status before the document is ever looked at, so the branch that builds a
 * `TrustTaskRejection` — and therefore the whole §8.4 retry policy below — was
 * unreachable against a real server while every test passed.
 */
const STATUS_FOR_CODE: Record<string, number> = {
  permissionDenied: 403,
  notFound: 404,
  malformedRequest: 400,
  taskFailed: 422,
  unavailable: 503,
  internalError: 500,
};

const jsonError = (body: { type: string; payload: { code: string } }): StubResponse => {
  const serialised = JSON.stringify(body);
  return {
    ok: false,
    status: STATUS_FOR_CODE[body.payload.code] ?? 500,
    statusText: "Error",
    headers: new Headers({ "content-type": "application/json" }),
    json: async () => body,
    text: async () => serialised,
  };
};

/** Serve success documents at 200 and error documents at their mapped status,
 *  the way the server does. */
const asResponse = (doc: unknown): StubResponse => {
  const type = (doc as { type?: unknown })?.type;
  return typeof type === "string" && type.includes("/trust-task-error/")
    ? jsonError(doc as { type: string; payload: { code: string } })
    : jsonOk(doc);
};

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
          return asResponse(next);
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

  it("a rejection at its real status is still a TrustTaskRejection with its payload", async () => {
    // The regression. A rejection arrives as a document at a NON-2xx status, so
    // `request()` throws on the status first. Without reading the body before
    // deciding, the document was discarded: the caller got a bare `ApiError`
    // whose message was the serialised JSON, and `retryDelayMs` — which reads
    // `code` and `retryable` off the payload — never ran, because nothing was
    // ever a `TrustTaskRejection`.
    stubFetch([errorResponse("permissionDenied", false)]);

    const promise = api.listAcl();
    const settled = expect(promise).rejects.toSatisfy(
      (e: unknown) =>
        e instanceof TrustTaskRejection &&
        e.payload.code === "permissionDenied" &&
        e.payload.retryable === false &&
        // …and it reports the status it actually arrived at, not a flat 422.
        e.status === 403,
    );
    await vi.runAllTimersAsync();
    await settled;
  });

  it("re-issues after a retryable rejection served at its real status", async () => {
    // The consequence of the above, and the behaviour the §8.4 policy exists
    // for: `unavailable` (503) provably did not run, so it is safe to re-issue.
    // This could not have worked while every rejection was a plain `ApiError`.
    stubFetch([errorResponse("unavailable", true), listResponse([])]);

    const promise = api.listAcl();
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.entries).toEqual([]);
    expect(trustTaskCalls).toBe(2);
  });

  it("a non-trust-task error body is left alone", async () => {
    // A proxy error page, an auth failure, anything that is not a framework
    // error document must surface as the `ApiError` it is — dressing it up as a
    // rejection would hand the retry policy fields nobody promised.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: string): Promise<StubResponse> => {
        if (path === "/api/server-info") {
          return jsonOk({ server_did: "did:webvh:example:test", version: "0" });
        }
        return {
          ok: false,
          status: 502,
          statusText: "Bad Gateway",
          headers: new Headers({ "content-type": "text/html" }),
          text: async () => "<html>gateway</html>",
          json: async () => {
            throw new Error("not json");
          },
        };
      }),
    );

    const promise = api.listAcl();
    const settled = expect(promise).rejects.toSatisfy(
      (e: unknown) => e instanceof ApiError && !(e instanceof TrustTaskRejection),
    );
    await vi.runAllTimersAsync();
    await settled;
  });
});
