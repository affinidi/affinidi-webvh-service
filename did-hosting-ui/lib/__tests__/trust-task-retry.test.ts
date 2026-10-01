/**
 * Tests for the trust-task retry policy in `lib/trust-task.ts`.
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
 * `acl/list` drives the end-to-end layer. Like every envelope but discovery it
 * is signed, so the session-key module is stubbed to attach a placeholder
 * proof — the fetch stub never verifies it — and a bearer token supplies the
 * subject DID the envelope's `issuer` is taken from.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  TrustTaskRejection,
  api,
  resetServiceInfo,
  retryDelayMs,
} from "../api";
import { resetSessionCacheForTests, setToken } from "../session";
import {
  SERVER_INFO,
  installControlPlane,
  tokenFor,
  jsonResponse,
  rejection,
  seal,
  type Doc,
  type StubResponse,
} from "./fake-control-plane";

vi.mock("../session-key", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../session-key")>()),
  hasSessionKeypair: () => true,
  restoreSessionKeypair: async () => {},
  signEnvelope: async (envelope: Record<string, unknown>) => {
    envelope.proof = { type: "DataIntegrityProof", proofValue: "zTest" };
    return envelope;
  },
}));


const SUBJECT = "did:web:admin.example";

const GRANT = "https://trusttasks.org/spec/acl/grant/0.1";
const REVOKE = "https://trusttasks.org/spec/acl/revoke/0.1";
const CHANGE_ROLE = "https://trusttasks.org/spec/acl/change-role/0.1";
const LIST = "https://trusttasks.org/spec/acl/list/0.1";
const SHOW = "https://trusttasks.org/spec/acl/show/0.1";

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

/** A `trust-task-error` document. */
const errorResponse = (code: string, retryable: boolean) => rejection(code, retryable);

/** A successful `acl/list` reply to whichever request it answers. */
const listResponse =
  (entries: unknown[]) =>
  (req: Doc): Doc =>
    seal(req, { entries, truncated: false });

describe("trustTask — re-issue behaviour", () => {
  let trustTaskCalls: number;

  /** Every ACL document sent, as the server would have received it. */
  let sent: Doc[];

  /** Answer `server/info` as the control plane does, and each other POST with
   *  the next queued reply (a document, or a function of the request). */
  function stubFetch(responses: (Doc | ((req: Doc) => Doc))[]) {
    trustTaskCalls = 0;
    sent = [];
    const queue = [...responses];
    installControlPlane((req) => {
      trustTaskCalls++;
      sent.push(req);
      const next = queue.shift();
      if (next === undefined) throw new Error("unexpected extra POST");
      return typeof next === "function" ? next(req) : next;
    });
  }

  beforeEach(() => {
    // `retryAfter`-less retries pause for TRUST_TASK_DEFAULT_RETRY_DELAY_MS;
    // fake timers keep the suite instant.
    vi.useFakeTimers();
    resetServiceInfo();
    resetSessionCacheForTests();
    setToken(tokenFor(SUBJECT));
  });

  it("signs an ACL read and names the session subject as its issuer", async () => {
    stubFetch([listResponse([])]);

    await api.listAcl();

    expect(sent).toHaveLength(1);
    expect(sent[0]!.issuer).toBe(SUBJECT);
    expect(sent[0]!.proof).toBeDefined();
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
      vi.fn(async (_path: string, init?: RequestInit): Promise<StubResponse> => {
        const doc = JSON.parse(String(init?.body ?? "{}")) as Doc;
        if (doc.type === SERVER_INFO) {
          return jsonResponse(
            seal(doc, { serviceDid: "did:webvh:example:test", agentNames: false, serviceNames: [] }, {
              issuer: "did:webvh:example:test",
              proof: {
                type: "DataIntegrityProof",
                cryptosuite: "eddsa-jcs-2022",
                verificationMethod: "did:webvh:example:test#key-0",
                proofPurpose: "authentication",
                proofValue: "zSig",
              },
            }),
          );
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
