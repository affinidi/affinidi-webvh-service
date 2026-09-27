/**
 * The Trust Task binding the console speaks to its control plane:
 * `POST /api/trust-tasks`, the HTTPS binding of the same dispatch the control
 * plane serves over TSP and DIDComm. Every management call is one document out
 * and one document back.
 *
 * Outbound, every document except the public `server/info` read carries an
 * `eddsa-jcs-2022` proof: from the wallet on a wallet login, or from the
 * ephemeral session key a passkey login bound to the session.
 *
 * Inbound, every non-error reply must be the control plane's own signed answer
 * to *this* request (see {@link checkReply}). The browser has no resolver for
 * the control plane's DID method, so it cannot check the signature bytes; what
 * it does check is everything that binds the reply to the request and to the
 * service: the response type, the thread, the parties, and a proof that names
 * a key of the service DID for `authentication`. An unsigned reply, or one
 * signed for someone else, is refused.
 */

import { ApiError, request } from "./http";
import {
  clearToken,
  getAuthMethod,
  getSessionPrincipalDid,
  getSessionSubjectDid,
} from "./session";
import {
  generateSessionKeypair,
  hasSessionKeypair,
  restoreSessionKeypair,
  signEnvelope,
} from "./session-key";
import type {
  Response as ServerInfoResponse,
  TYPE_URI as SERVER_INFO_URI,
} from "@openvtc/trust-tasks/did-management/server/info/0.1/payload";

/** The Trust Task endpoint on the control plane. */
export const TRUST_TASKS_PATH = "/api/trust-tasks";

const TT_RESPONSE_FRAGMENT = "#response";

const SERVER_INFO: typeof SERVER_INFO_URI =
  "https://trusttasks.org/spec/did-management/server/info/0.1";

/**
 * Is this reply document a framework error document, at any `0.x` minor?
 *
 * Matched by slug rather than pinned to a version. This was `=== ".../0.1"`,
 * and `trust-tasks-rs` has emitted `trust-task-error/0.3` since its 0.3 release
 * (it carries the §8.2 `inResponseTo` member, which `0.2`'s
 * `additionalProperties: false` payload schema cannot admit) — so the control
 * plane this UI talks to, on 0.4.1, has not sent a document this recognised in
 * some time. SPEC.md §5.2's forward-minor rule says a consumer SHOULD accept a
 * later minor; matching the slug means the next one cannot break it again.
 * `1.x` is excluded on purpose: a major bump is where the payload shape may
 * change, and `TrustTaskErrorPayload` is read directly off it.
 */
function isTrustTaskErrorType(type: string | undefined): boolean {
  if (typeof type !== "string") return false;
  return /^https:\/\/trusttasks\.org\/spec\/trust-task-error\/0\.\d+$/.test(type);
}

/** Outer envelope shape produced by every `trustTask()` call. */

/** A Data Integrity proof, as far as the console reads one. */
export interface DocumentProof {
  type?: unknown;
  cryptosuite?: unknown;
  verificationMethod?: unknown;
  proofPurpose?: unknown;
  proofValue?: unknown;
  created?: unknown;
}

/** A Trust Task document, request or reply. */
export interface TrustTaskDocument<P> {
  id: string;
  type: string;
  threadId?: string;
  issuer?: string;
  recipient?: string;
  issuedAt?: string;
  payload: P;
  proof?: DocumentProof;
}

/** `trust-task-error` payload shape. Mirrors `trust_tasks_rs::ErrorPayload`. */
export interface TrustTaskErrorPayload {
  code: string;
  message?: string;
  retryable: boolean;
  retryAfter?: string;
  details?: unknown;
}

/**
 * Recover a {@link TrustTaskRejection} from an {@link ApiError} whose body is a
 * framework error document, or `null` when it is anything else.
 *
 * Deliberately strict about what counts: the type must be a framework error
 * document and the payload must carry a `code`. A body that merely happens to
 * be JSON — an HTML error page is not, but a reverse proxy's `{"error": …}` is
 * — must not be dressed up as a Trust-Task rejection, or the retry policy would
 * be reading fields off a shape nobody promised.
 */
function trustTaskRejectionFrom(err: ApiError): TrustTaskRejection | null {
  if (!err.body) return null;
  let doc: { type?: unknown; payload?: unknown };
  try {
    doc = JSON.parse(err.body);
  } catch {
    return null;
  }
  if (!isTrustTaskErrorType(typeof doc?.type === "string" ? doc.type : undefined)) {
    return null;
  }
  const payload = doc.payload as TrustTaskErrorPayload | undefined;
  if (!payload || typeof payload.code !== "string") return null;
  return new TrustTaskRejection(
    payload.message ?? payload.code ?? "trust task rejected",
    payload,
    err.status,
  );
}

export class TrustTaskRejection extends ApiError {
  constructor(
    message: string,
    public payload: TrustTaskErrorPayload,
    // The status the rejection actually arrived at. `status_for_code` maps the
    // framework code onto it (permissionDenied → 403, notFound → 404,
    // taskFailed → 422), so reporting a flat 422 for all of them told anything
    // reading `.status` — an error banner, a redirect on 401/403 — the wrong
    // thing. Defaults to 422 for the 2xx-bodied path, which carries no status
    // of its own.
    status = 422,
  ) {
    super(status, message);
    this.name = "TrustTaskRejection";
  }
}

/**
 * The code that is safe to auto-retry on *any* task.
 *
 * `unavailable` is the spec's unambiguous "temporarily unable to process"
 * (SPEC §8.3) — the task did **not** run, so re-issuing cannot double-apply
 * a mutation.
 */
const ALWAYS_RETRY_CODES = new Set<string>(["unavailable"]);

/**
 * Task types where re-issuing is safe even when the error is *ambiguous*
 * about whether the first attempt took effect (`internalError`) — either
 * because the task has no side effects, or because applying it twice is
 * a no-op.
 *
 * This is the distinction that makes honoring the flag useful against
 * this control plane at all: it emits `internalError` (retryable by
 * default in `trust_tasks_rs`) but never `unavailable`, so a code-only
 * policy would be inert. Safety comes from what the *task* does, not from
 * the code.
 *
 * Membership is a claim about the maintainer's semantics, so each entry
 * cites the rule that makes it true:
 *
 * * `acl/list`, `acl/show`, and the did-management, stats, server and
 *   invite reads below — reads. Nothing to duplicate. (`did/check-name` is
 *   not here: with `reserve: true` it claims a slot.)
 * * `acl/grant` — idempotent by SPEC §3, "re-emitting an identical grant
 *   produces no state change". The handler's equal-role arm merges the
 *   producer's metadata and persists only when a field actually changed
 *   (`handlers/grant.rs`), so a re-issue after a first attempt that
 *   silently succeeded is a no-op.
 *
 * Deliberately excluded — and *not* because they would corrupt state;
 * both fail cleanly on re-issue — but because the failure would be
 * misleading, reporting an error for an operation that succeeded:
 *
 * * `acl/revoke` — a re-issue after a successful full removal is
 *   rejected `acl/revoke:subject_not_present`.
 * * `acl/change-role` — state-checked against `fromRole`, so a re-issue
 *   after success is rejected `acl/change-role:state_mismatch`.
 *
 * Enumerated rather than derived as "not a mutation", so a future
 * proofless *write* cannot silently inherit auto-retry. Adding an entry
 * means answering: if the first attempt already took effect, is a second
 * one a no-op?
 */
const REISSUE_SAFE_TASK_TYPES = new Set<string>([
  "https://trusttasks.org/spec/acl/list/0.1",
  "https://trusttasks.org/spec/acl/show/0.1",
  "https://trusttasks.org/spec/acl/grant/0.1",
  "https://trusttasks.org/spec/did-management/did/list/0.1",
  "https://trusttasks.org/spec/did-management/did/info/0.1",
  "https://trusttasks.org/spec/did-management/did/log/0.1",
  "https://trusttasks.org/spec/did-management/agent-name/check/0.1",
  "https://trusttasks.org/spec/did-management/agent-name/resolve/0.1",
  "https://trusttasks.org/spec/did-management/domain/list/0.1",
  "https://trusttasks.org/spec/did-management/me/domains/0.1",
  "https://trusttasks.org/spec/did-management/registry/list/0.1",
  "https://trusttasks.org/spec/did-management/registry/get/0.1",
  "https://trusttasks.org/spec/did-management/stats/get/0.1",
  "https://trusttasks.org/spec/did-management/stats/timeseries/0.1",
  "https://trusttasks.org/spec/did-management/server/info/0.1",
  "https://trusttasks.org/spec/did-management/server/config/0.1",
  "https://trusttasks.org/spec/did-management/server/metrics/0.1",
  "https://trusttasks.org/spec/did-management/identity/list/0.1",
  "https://trusttasks.org/spec/auth/passkey/enroll/invite/list/0.1",
]);

/** Codes that are retryable per the framework but ambiguous about whether
 *  the task ran — honored only on a `REISSUE_SAFE_TASK_TYPES` task. */
const AMBIGUOUS_RETRY_CODES = new Set<string>(["internalError"]);

/** Extra attempts after the first. One is enough to ride out a restart or
 *  a brief mediator hiccup; more would just delay showing the user a real
 *  failure. */
const TRUST_TASK_MAX_RETRIES = 1;

/** Cap on an honored `retryAfter`, so a server can't park the UI on a
 *  spinner. Past this we surface the error and let the user retry. */
const TRUST_TASK_MAX_RETRY_DELAY_MS = 5_000;

/** Fallback pause when the server marks an error retryable but gives no
 *  `retryAfter`. */
const TRUST_TASK_DEFAULT_RETRY_DELAY_MS = 500;

/**
 * Apply SPEC §8.4 retry semantics to a rejection, returning how long to
 * wait before re-issuing, or `null` to give up and surface the error.
 *
 * Mirrors `trust_tasks_rs::ErrorPayload::should_retry_at`: retry only when
 * `retryable` is set and any `retryAfter` has elapsed. We additionally
 * *wait out* a near-future `retryAfter` rather than failing on it, which
 * is what makes the hint useful in an interactive UI.
 *
 * Exported for `lib/__tests__/trust-task-retry.test.ts`; not part of the
 * client surface.
 */
export function retryDelayMs(
  typeUri: string,
  payload: TrustTaskErrorPayload,
  now: number,
): number | null {
  // The server's flag is necessary but not sufficient: it says "retrying
  // is allowed", not "re-issuing this particular task is safe".
  if (!payload.retryable) return null;
  const safe =
    ALWAYS_RETRY_CODES.has(payload.code) ||
    (AMBIGUOUS_RETRY_CODES.has(payload.code) &&
      REISSUE_SAFE_TASK_TYPES.has(typeUri));
  if (!safe) return null;

  if (payload.retryAfter === undefined) {
    return TRUST_TASK_DEFAULT_RETRY_DELAY_MS;
  }
  const at = Date.parse(payload.retryAfter);
  // An unparseable hint is not a reason to hammer the server.
  if (Number.isNaN(at)) return null;
  const wait = at - now;
  if (wait <= 0) return 0;
  return wait <= TRUST_TASK_MAX_RETRY_DELAY_MS ? wait : null;
}

// ---------------------------------------------------------------------------
// Reply binding
// ---------------------------------------------------------------------------

/** The proof purpose the control plane signs its replies with. */
const REPLY_PROOF_PURPOSE = "authentication";

/**
 * Refuse a reply that is not the service's signed answer to `sent`.
 *
 * Checked, in order:
 *
 * 1. `type` is the request's type plus `#response`.
 * 2. `threadId` is the request's `id` — the control plane threads every reply
 *    to the document it answers, so a reply to some other request (a cached
 *    one, a replayed one) is refused.
 * 3. `issuer` is `serviceDid`.
 * 4. `recipient`, when the request named an issuer, is that issuer: the
 *    answer is addressed to whoever asked.
 * 5. A `DataIntegrityProof`, `eddsa-jcs-2022`, `proofPurpose: authentication`,
 *    whose `verificationMethod` is a key of `serviceDid`, with a
 *    `proofValue`.
 *
 * Throws an {@link ApiError} (status 502: the upstream answered with
 * something the console will not accept) naming the first failure.
 *
 * Error documents are not passed here: the framework lets a
 * `trust-task-error` travel unsigned, and a rejection authorises nothing.
 */
export function checkReply(
  sent: Pick<TrustTaskDocument<unknown>, "id" | "type" | "issuer">,
  reply: TrustTaskDocument<unknown>,
  serviceDid: string,
): void {
  const refuse = (why: string): never => {
    throw new ApiError(502, `refused the reply to ${sent.type}: ${why}`);
  };
  if (reply.type !== sent.type + TT_RESPONSE_FRAGMENT) {
    refuse(`unexpected type ${String(reply.type)}`);
  }
  if (reply.threadId !== sent.id) {
    refuse("it does not answer this request");
  }
  if (reply.issuer !== serviceDid) {
    refuse(`issued by ${String(reply.issuer)}, not the service ${serviceDid}`);
  }
  if (sent.issuer !== undefined && reply.recipient !== sent.issuer) {
    refuse(`addressed to ${String(reply.recipient)}, not ${sent.issuer}`);
  }
  const proof = reply.proof;
  if (!proof || typeof proof !== "object") {
    refuse("it is unsigned");
  }
  const p = proof as DocumentProof;
  if (p.type !== "DataIntegrityProof" || p.cryptosuite !== "eddsa-jcs-2022") {
    refuse("its proof is not an eddsa-jcs-2022 Data Integrity proof");
  }
  if (p.proofPurpose !== REPLY_PROOF_PURPOSE) {
    refuse(`its proof purpose is ${String(p.proofPurpose)}, not ${REPLY_PROOF_PURPOSE}`);
  }
  if (
    typeof p.verificationMethod !== "string" ||
    !p.verificationMethod.startsWith(serviceDid + "#")
  ) {
    refuse(`signed by ${String(p.verificationMethod)}, not a key of ${serviceDid}`);
  }
  if (typeof p.proofValue !== "string" || !p.proofValue.startsWith("z")) {
    refuse("its proof carries no signature");
  }
}

// ---------------------------------------------------------------------------
// The service's identity
// ---------------------------------------------------------------------------

let cachedServiceInfo: Promise<ServerInfoResponse> | null = null;

/**
 * `did-management/server/info/0.1`: the service DID every other document is
 * addressed to, plus the public facts the console renders before login.
 *
 * Sent anonymously (no bearer, no proof — the one public read). The reply must
 * be signed by the `serviceDid` it names, so a reply that names one DID and is
 * signed by another is refused. Cached for the tab: the service DID is stable
 * per deployment. A failed read is not cached.
 */
export function getServiceInfo(): Promise<ServerInfoResponse> {
  if (!cachedServiceInfo) {
    cachedServiceInfo = fetchServiceInfo().catch((e) => {
      cachedServiceInfo = null;
      throw e;
    });
  }
  return cachedServiceInfo;
}

/** Forget the cached service info. For tests. */
export function resetServiceInfo(): void {
  cachedServiceInfo = null;
}

async function fetchServiceInfo(): Promise<ServerInfoResponse> {
  const sent: TrustTaskDocument<Record<string, never>> = {
    id: `urn:uuid:${cryptoRandomUuid()}`,
    type: SERVER_INFO,
    issuedAt: new Date().toISOString(),
    payload: {},
  };
  const reply = await post<ServerInfoResponse>(sent, { anonymous: true });
  const serviceDid = reply.payload?.serviceDid;
  if (typeof serviceDid !== "string" || serviceDid.length === 0) {
    throw new ApiError(502, "server/info named no service DID");
  }
  checkReply(sent, reply, serviceDid);
  return reply.payload;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/** Who signs a document, and as whom. */
export type Signer =
  /** The session's subject: the wallet on a wallet login, the session key on a
   *  passkey login. The default. */
  | "session"
  /** The session key itself, as its own `did:key` issuer — a passkey login's
   *  finish, which binds the new session to the key that signs it. A fresh
   *  key pair is generated for it. */
  | "fresh-session-key"
  /** No proof and no issuer — only for a task whose proof rule is optional
   *  and that authorises nothing (opening a passkey login ceremony). */
  | "none";

export interface TrustTaskOptions {
  signer?: Signer;
  /** Send no bearer token. A document signed by a key the session does not
   *  have yet (`fresh-session-key`) must not carry the old session's. */
  anonymous?: boolean;
}

interface WalletSigner {
  signTrustTask: (p: {
    envelope: Record<string, unknown>;
    asDid?: string;
  }) => Promise<{ signedEnvelope: Record<string, unknown> }>;
}

/** Attach the proof `signer` calls for, setting `issuer` to match. */
async function sign(
  doc: TrustTaskDocument<unknown>,
  signer: Signer,
): Promise<TrustTaskDocument<unknown>> {
  if (signer === "none") return doc;
  if (signer === "fresh-session-key") {
    const { didKey } = await generateSessionKeypair();
    doc.issuer = didKey;
    await signEnvelope(doc as unknown as Record<string, unknown>);
    return doc;
  }

  const subject = getSessionSubjectDid();
  if (!subject) {
    throw new ApiError(
      401,
      "Not signed in — trust tasks need an authenticated session to sign as.",
    );
  }
  doc.issuer = subject;

  if (getAuthMethod() === "wallet") {
    // Wallet login. A holder login's session is the wallet's own DID, so it
    // signs as itself; a proxy login's session is a vault entry's principal,
    // whose key lives at the VTA, so the wallet asks the VTA to sign as that
    // DID (`asDid`). Without it the proof would name the holder and the
    // control plane would refuse it as not the authenticated caller.
    const wallet =
      typeof window !== "undefined"
        ? (window as unknown as { vtaWallet?: WalletSigner }).vtaWallet
        : undefined;
    if (!wallet?.signTrustTask) {
      throw new ApiError(
        401,
        "Wallet-authenticated session but the VTA Wallet extension is not available to sign. Re-install the extension or log out + back in with passkey.",
      );
    }
    const principal = getSessionPrincipalDid();
    const signed = await wallet.signTrustTask({
      envelope: doc as unknown as Record<string, unknown>,
      ...(principal ? { asDid: principal } : {}),
    });
    // The wallet returns the document with `proof` added; every other member
    // must be byte-identical, or the control plane's JCS hash will not match.
    return signed.signedEnvelope as unknown as TrustTaskDocument<unknown>;
  }

  // Passkey login: the session key the login bound to this session. Restored
  // from IndexedDB after a reload. There is deliberately no fallback to a new
  // key — the control plane would refuse its proof, and the user must sign in
  // again.
  if (!hasSessionKeypair()) {
    await restoreSessionKeypair();
  }
  if (!hasSessionKeypair()) {
    clearToken();
    if (typeof window !== "undefined") {
      window.dispatchEvent(new Event("webvh:unauthorized"));
    }
    throw new ApiError(
      401,
      "This browser no longer holds the session key — sign in again.",
    );
  }
  await signEnvelope(doc as unknown as Record<string, unknown>);
  return doc;
}

/**
 * POST one document and return the reply document, un-checked. A
 * `trust-task-error` reply — at a non-2xx status, as the control plane sends
 * it, or at a 2xx — is thrown as a {@link TrustTaskRejection}.
 */
async function post<Resp>(
  doc: TrustTaskDocument<unknown>,
  opts: { anonymous?: boolean } = {},
): Promise<TrustTaskDocument<Resp>> {
  let reply: TrustTaskDocument<Resp | TrustTaskErrorPayload>;
  try {
    reply = await request<TrustTaskDocument<Resp | TrustTaskErrorPayload>>(
      TRUST_TASKS_PATH,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(doc),
        anonymous: opts.anonymous,
      },
    );
  } catch (e) {
    // A rejection is a *document* at a non-2xx status (`status_for_code`:
    // permissionDenied → 403, taskFailed → 422, …). Read the body before
    // deciding what the failure was; anything that is not a trust-task error
    // document — a proxy error page, a network fault — is re-thrown untouched.
    const rejection = e instanceof ApiError ? trustTaskRejectionFrom(e) : null;
    if (rejection) throw rejection;
    throw e;
  }
  if (!reply || typeof reply !== "object" || typeof reply.type !== "string") {
    throw new ApiError(502, "the control plane answered with no Trust Task document");
  }
  if (isTrustTaskErrorType(reply.type)) {
    const err = reply.payload as TrustTaskErrorPayload;
    throw new TrustTaskRejection(err.message ?? err.code ?? "trust task rejected", err);
  }
  return reply as TrustTaskDocument<Resp>;
}

/**
 * Build, sign, send and check one document; return its reply payload.
 *
 * Every document names the service DID as `recipient` (the audience binding a
 * signature needs, and required in-band by every spec the console sends).
 */
async function sendOnce<Req, Resp>(
  typeUri: string,
  payload: Req,
  opts: TrustTaskOptions,
): Promise<Resp> {
  const { serviceDid } = await getServiceInfo();
  const unsigned: TrustTaskDocument<Req> = {
    id: `urn:uuid:${cryptoRandomUuid()}`,
    type: typeUri,
    recipient: serviceDid,
    issuedAt: new Date().toISOString(),
    payload,
  };
  const doc = await sign(unsigned, opts.signer ?? "session");
  const reply = await post<Resp>(doc, { anonymous: opts.anonymous });
  checkReply(doc, reply, serviceDid);
  return reply.payload;
}

/**
 * Send a trust task, honoring the server's `retryable` / `retryAfter` hints
 * (SPEC §8.4).
 *
 * Every attempt builds a **fresh** document — new `id`, new `issuedAt`, a new
 * proof — because a bit-for-bit resend of a signed document would be refused
 * as a replay. A re-issued document is a *new* task, so auto-retry is limited
 * to `unavailable` (the task did not run) and to `internalError` on tasks
 * where a second application is a no-op. See `REISSUE_SAFE_TASK_TYPES`.
 */
export async function trustTask<Req, Resp>(
  typeUri: string,
  payload: Req,
  opts: TrustTaskOptions = {},
): Promise<Resp> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await sendOnce<Req, Resp>(typeUri, payload, opts);
    } catch (e) {
      if (!(e instanceof TrustTaskRejection) || attempt >= TRUST_TASK_MAX_RETRIES) {
        throw e;
      }
      const delay = retryDelayMs(typeUri, e.payload, Date.now());
      if (delay === null) throw e;
      // eslint-disable-next-line no-console
      console.debug(
        `trust task ${typeUri} rejected as ${e.payload.code} (retryable); re-issuing in ${delay}ms`,
      );
      if (delay > 0) {
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
}

/** Is `e` a rejection carrying `code` (bare, or namespaced `family:code`)? */
export function isRejection(e: unknown, code: string): e is TrustTaskRejection {
  if (!(e instanceof TrustTaskRejection)) return false;
  const c = e.payload.code;
  return c === code || c.endsWith(":" + code);
}

/** Browser-safe UUIDv4. Falls back to a polyfill where crypto.randomUUID
 * isn't available (e.g. iOS Safari < 15.4). */
function cryptoRandomUuid(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // RFC 4122 v4 polyfill via getRandomValues.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex
    .slice(6, 8)
    .join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}

