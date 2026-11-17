/**
 * The browser's session state: the bearer tokens, which login produced them,
 * and what the access token says about the session.
 *
 * Nothing here is trusted for authorisation — the control plane verifies the
 * token and the document proof on every request. The UI reads the claims only
 * to name its own `issuer` and the session it asks to step up.
 *
 * Storage: the access token, refresh token and auth method live in an
 * in-memory cache first — every read in this module is synchronous and never
 * touches storage. The cache is mirrored to IndexedDB (fire-and-forget on
 * write) so a reload can restore it, and lazily restored from there the same
 * way `session-key.ts` restores the signing keypair. Never `localStorage`,
 * which a generic scrape enumerates in one line
 * (`Object.entries(localStorage)`).
 *
 * IndexedDB is not a boundary, though: any script running on this origin can
 * read these tokens from it, or from this module's memory. What protects a
 * session against such a script is the session keypair, which is generated
 * non-extractable (`session-key.ts`) and so cannot be copied out. The control
 * plane requires a proof on every task that acts (a bearer token alone is
 * refused with `proofRequired`), and a browser session's proofs are made with
 * that key; refreshing a session that bound a key also needs its proof. A
 * script on the origin can still use the key while the page is open — keeping
 * script off the origin (the CSP) is the boundary for that.
 *
 * Sign-out reaches every tab: `clearToken` announces it on a
 * `BroadcastChannel`, and a tab holding the same session drops its copy
 * ([`listenForSignOut`]).
 */

import {
  clearSessionKeypair,
  forgetSessionKeypair,
  hasSessionKeypair,
  restoreSessionKeypair,
} from "./session-key";
import { T } from "./task-types";
import type {
  Payload as RefreshPayload,
  Response as RefreshResponse,
} from "./trust-tasks/auth/refresh/0.2/payload";
// `trust-task.ts` imports `clearToken`/`getSessionSubjectDid` from this
// module, so a static top-level import back the other way is a genuine
// cycle, not one that "resolves fine": `trust-task.ts` declares `class
// TrustTaskRejection extends ApiError` at module-eval time, and whichever of
// the two modules a caller reaches first leaves the other only partially
// evaluated when that class body runs — `ApiError` is still unbound and the
// `extends` throws. A dynamic `import()` inside `refreshWithSessionKey` below defers
// the load until first call, by which point both modules have finished
// evaluating.

/** Which auth path produced the current session. Passkey, wallet holder and
 *  wallet proxy logins all bind the browser's session keypair, which then
 *  signs trust tasks; a session whose key this browser no longer holds ends.
 *  Only step-up branches on this: a wallet session steps up through the
 *  wallet. */
export type AuthMethod = "passkey" | "wallet";

// ---------------------------------------------------------------------------
// In-memory cache + IndexedDB persistence
// ---------------------------------------------------------------------------

let accessTokenMem: string | null = null;
let refreshTokenMem: string | null = null;
let authMethodMem: AuthMethod | null = null;

/** Cached promise of an in-flight IDB restore; coalesces concurrent callers
 *  onto one round-trip, exactly like `session-key.ts`'s `restoreInFlight`. */
let sessionRestoreInFlight: Promise<void> | null = null;
/** Set once a restore (successful or not) has completed, so later callers —
 *  everything after the first page paint — skip the round-trip entirely. */
let sessionRestored = false;

type PersistedSession = {
  accessToken: string | null;
  refreshToken: string | null;
  authMethod: AuthMethod | null;
};

const IDB_NAME = "did-hosting-ui-session";
const IDB_STORE = "tokens";
const IDB_VERSION = 1;
/** Stable key for the one-and-only persisted record. */
const SESSION_KEY = "current";

/** Open (or upgrade-and-open) the per-origin database. Returns `null` when
 *  IndexedDB is unavailable — callers then treat persistence as a no-op, the
 *  same fallback `session-key.ts` uses. */
function openDb(): Promise<IDBDatabase | null> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      resolve(null);
      return;
    }
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB.open failed"));
    req.onblocked = () => reject(new Error("indexedDB.open blocked by an older connection"));
  });
}

/** Persist the whole cache in one record, so a write to one field never
 *  clobbers the others — the caller always passes the in-memory values it
 *  just updated alongside whatever it did not touch. */
async function idbPutSession(value: PersistedSession): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readwrite");
    tx.objectStore(IDB_STORE).put(value, SESSION_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IDB put failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IDB put aborted"));
  });
  db.close();
}

async function idbGetSession(): Promise<PersistedSession | undefined> {
  const db = await openDb();
  if (!db) return undefined;
  try {
    return await new Promise<PersistedSession | undefined>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readonly");
      const req = tx.objectStore(IDB_STORE).get(SESSION_KEY);
      req.onsuccess = () => resolve(req.result as PersistedSession | undefined);
      req.onerror = () => reject(req.error ?? new Error("IDB get failed"));
    });
  } finally {
    db.close();
  }
}

async function idbDeleteSession(): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readwrite");
    tx.objectStore(IDB_STORE).delete(SESSION_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IDB delete failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IDB delete aborted"));
  });
  db.close();
}

/** Best-effort mirror of the in-memory cache to IndexedDB. Fire-and-forget —
 *  callers never await this, so a slow or failing write cannot block login,
 *  a request, or logout. */
function persistSession(): void {
  idbPutSession({
    accessToken: accessTokenMem,
    refreshToken: refreshTokenMem,
    authMethod: authMethodMem,
  }).catch((e) => {
    console.warn("session: IDB persist failed", e);
  });
}

/**
 * Restore the access token, refresh token and auth method from IndexedDB
 * into the in-memory cache. No-op once a restore has already run this page
 * load (successful or not) — the cache is then the single source of truth
 * and only this module's own writes change it.
 *
 * Callers that read the cache without going through `request()` first
 * (`AuthProvider`'s mount effect, `api.logout()`, `api.stepUp()`) await this
 * so a cold reload sees the same session `request()` would.
 */
export async function restoreSession(): Promise<void> {
  if (sessionRestored) return;
  if (sessionRestoreInFlight) return sessionRestoreInFlight;

  sessionRestoreInFlight = (async () => {
    try {
      const persisted = await idbGetSession();
      if (persisted) {
        accessTokenMem = persisted.accessToken;
        refreshTokenMem = persisted.refreshToken;
        authMethodMem = persisted.authMethod;
      }
    } catch (e) {
      console.warn("session: IDB restore failed", e);
    } finally {
      sessionRestored = true;
      sessionRestoreInFlight = null;
    }
  })();
  return sessionRestoreInFlight;
}

export function getToken(): string | null {
  return accessTokenMem;
}

export function setToken(token: string): void {
  accessTokenMem = token;
  persistSession();
}

/// The refresh token, which login used to hand us and we used to discard.
///
/// Without it the console could not renew: the access token is a fixed
/// 15-minute JWT, nothing extended it, and the first sign of expiry was a
/// request failing. It lives beside the access token in the same in-memory
/// cache and the same IndexedDB record — no worse a place, since a reader of
/// one already has the other.
export function getRefreshToken(): string | null {
  return refreshTokenMem;
}

export function setRefreshToken(token: string | null): void {
  refreshTokenMem = token;
  persistSession();
}

/**
 * Reset the in-memory token cache to empty, without touching IndexedDB or
 * the session keypair. For tests: a suite that seeds one session per `it()`
 * (`fake-control-plane.ts`'s `stubStorage`) needs a clean cache first, since
 * the cache is a module-scope singleton that otherwise leaks a token from
 * one test into the next.
 */
export function resetSessionCacheForTests(): void {
  accessTokenMem = null;
  refreshTokenMem = null;
  authMethodMem = null;
  sessionRestored = true;
  sessionRestoreInFlight = null;
  renewInFlight = null;
  lastRenewAttemptMs = 0;
  transientRenewFailures = 0;
}

const REFRESH_TASK_URI = T.refresh;

/**
 * A JWT's payload claims, read without verification — the one decoder the
 * console has (see the module doc for why reading unverified is fine here).
 *
 * The payload is base64url: `-` and `_` in place of `+` and `/`, and no `=`
 * padding. Plain `atob` refuses those, so they are mapped back and the
 * padding restored first; the bytes are then decoded as UTF-8, so a claim
 * with non-ASCII text survives. `null` for anything that is not a JWT with a
 * JSON-object payload.
 */
export function decodeJwtPayload(token: string | null | undefined): Record<string, unknown> | null {
  const payload = token?.split(".")[1];
  if (!payload) return null;
  try {
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const claims: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return claims !== null && typeof claims === "object" && !Array.isArray(claims)
      ? (claims as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Seconds since the epoch at which `token` expires, or null if unreadable. */
function tokenExpiry(token: string): number | null {
  const exp = decodeJwtPayload(token)?.exp;
  return typeof exp === "number" ? exp : null;
}

/** Renew when the access token has this long or less to live. */
const RENEW_WITHIN_SECS = 60;
/** Floor between renewal attempts, so a failing one cannot spin. Doubled
 *  after each consecutive transient failure, up to {@link MAX_RETRY_GAP_MS}. */
const MIN_RETRY_GAP_MS = 5_000;
/** Ceiling on the backoff between renewals that keep failing transiently. */
const MAX_RETRY_GAP_MS = 60_000;

let renewInFlight: Promise<void> | null = null;
let lastRenewAttemptMs = 0;
/** Renewals in a row that failed for a reason worth trying again (network,
 *  a 5xx, `unavailable`); reset by a success. Drives the backoff. */
let transientRenewFailures = 0;

/** How long to wait after the last attempt before the next one. */
function renewRetryGapMs(): number {
  if (transientRenewFailures === 0) return MIN_RETRY_GAP_MS;
  return Math.min(MIN_RETRY_GAP_MS * 2 ** (transientRenewFailures - 1), MAX_RETRY_GAP_MS);
}

/**
 * The control plane refused a renewal for good: the session reached its
 * absolute lifetime, idled out, was revoked or is unknown, or this browser
 * lost the key it is bound to. Nothing a retry can change — only a fresh
 * sign-in. Thrown by the renewal, after the session has been ended here.
 */
export class SessionEndedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionEndedError";
  }
}

/**
 * Is `e`, thrown by a renewal, a refusal no retry can change?
 *
 * A Trust Task rejection says so itself: the control plane marks every
 * terminal refusal of `auth/refresh` non-retryable (`permissionDenied` for an
 * idled-out, revoked or unknown session; `auth/refresh:sessionLifetimeExceeded`
 * and the other `auth/refresh:*` codes) and a failure of its own
 * `unavailable`, which is retryable. A 401 is the session key gone from this
 * browser. Anything else — a network error, a proxy's 5xx page, a reply that
 * failed its checks — says nothing about the session, so it is transient.
 *
 * Read by shape, not `instanceof`: `trust-task.ts` and `http.ts` import this
 * module, and a static import back would be the cycle the note at the top
 * of this file describes.
 */
function isTerminalRefusal(e: unknown): boolean {
  if (e instanceof SessionEndedError) return true;
  if (!(e instanceof Error)) return false;
  const err = e as Error & { status?: unknown; payload?: { retryable?: unknown } };
  if (e.name === "TrustTaskRejection" && err.payload) {
    return err.payload.retryable !== true;
  }
  return e.name === "ApiError" && err.status === 401;
}

/**
 * End the session after the control plane refused to renew it for good —
 * once: the tokens are gone after this, so no later renewal starts. Clears
 * the tokens and the session key here, tells the other tabs holding the
 * session (`clearToken`'s broadcast) so they stop renewing it too, and raises
 * the "session expired — sign in again" prompt (`webvh:unauthorized`).
 *
 * Only while `refused` is still the refresh token held: a sign-in that landed
 * while the renewal was in flight is a different session, and stays.
 */
function endSessionAfterRefusal(refused: string): void {
  if (refreshTokenMem !== refused) return;
  clearToken();
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event("webvh:unauthorized"));
  }
}

/**
 * Renew the session if the access token is nearly out.
 *
 * Single-flight, and that matters more than ordinary dedupe: refresh
 * **rotates** the token and the daemon claims the old one atomically, so a
 * second simultaneous renewal would present a token the first had already
 * consumed and be rejected.
 *
 * Sent as an `auth/refresh/0.2` Trust Task over `POST /api/trust-tasks` —
 * there is no dedicated REST refresh route any more. The daemon refuses a
 * renewal once the session has been idle past `auth.admin_idle_timeout`
 * (its own policy layered in front of the shared handler, unrelated to the
 * Trust Task spec), which is what stops this timer from keeping a tab
 * signed in forever, and once the session has reached its
 * `absoluteExpiresAt` — that one only a fresh sign-in can lift.
 *
 * Never throws. A refusal no retry can change ends the session here, once,
 * in every tab (see {@link endSessionAfterRefusal}), so nothing sends the
 * refused token again. Any other failure leaves the session alone, backs the
 * next attempt off, and lets the caller's own request report it.
 */
export async function renewIfNeeded(): Promise<void> {
  // After a reload the cache is empty until this restores it — same reason
  // the session keypair restore below exists.
  await restoreSession();
  const access = getToken();
  const refresh = getRefreshToken();
  if (!access || !refresh) return;

  const exp = tokenExpiry(access);
  if (exp === null) return;
  const now = Math.floor(Date.now() / 1000);
  if (now < exp - RENEW_WITHIN_SECS) return;

  if (renewInFlight) return renewInFlight;
  if (Date.now() - lastRenewAttemptMs < renewRetryGapMs()) return;
  lastRenewAttemptMs = Date.now();

  renewInFlight = (async () => {
    try {
      await refreshWithSessionKey(refresh);
    } catch {
      // Swallowed by design — see the doc comment. A terminal refusal has
      // already ended the session inside `refreshWithSessionKey`.
    } finally {
      renewInFlight = null;
    }
  })();
  return renewInFlight;
}

/**
 * Renew the session now, whatever the access token's remaining life, and
 * throw if it does not renew. A step-up calls this once the control plane has
 * raised the session's level: `auth/refresh` re-reads the session, so the
 * tokens it mints carry the new level.
 *
 * The renewal is signed by this browser's session key and spends the refresh
 * token held here — neither leaves the console. A timer renewal already in
 * flight is waited for first, because it rotates the refresh token this one
 * would otherwise present.
 */
export async function renewSessionNow(): Promise<void> {
  await restoreSession();
  if (renewInFlight) await renewInFlight;
  const refresh = getRefreshToken();
  if (!refresh) {
    throw new Error("No refresh token for this session — sign in again.");
  }
  const run = refreshWithSessionKey(refresh);
  const slot: Promise<void> = run
    .then(
      () => undefined,
      () => undefined,
    )
    .finally(() => {
      if (renewInFlight === slot) renewInFlight = null;
    });
  renewInFlight = slot;
  lastRenewAttemptMs = Date.now();
  await run;
}

/**
 * Send one `auth/refresh/0.2`, signed by the session key, and keep the tokens
 * it returns. Throws on any failure; the callers decide whether that matters.
 *
 * A terminal refusal ({@link isTerminalRefusal}) ends the session before it
 * is thrown, as a {@link SessionEndedError}, whichever caller asked; a
 * transient failure is rethrown as it is and counted towards the backoff.
 */
async function refreshWithSessionKey(refresh: string): Promise<void> {
  try {
    await sendRefresh(refresh);
    transientRenewFailures = 0;
  } catch (e) {
    if (isTerminalRefusal(e)) {
      endSessionAfterRefusal(refresh);
      throw e instanceof SessionEndedError
        ? e
        : new SessionEndedError(
            e instanceof Error ? e.message : "The session ended — sign in again.",
          );
    }
    transientRenewFailures += 1;
    throw e;
  }
}

async function sendRefresh(refresh: string): Promise<void> {
  // After a reload the key is only in IndexedDB. Without restoring it
  // first, the refresh would go out unsigned and be refused — every
  // login this UI offers binds one, so in practice this always signs.
  if (!hasSessionKeypair()) {
    await restoreSessionKeypair();
  }
  if (!hasSessionKeypair()) {
    throw new SessionEndedError("This browser no longer holds the session key — sign in again.");
  }

  // Through the one Trust Task client, so the reply is checked like every
  // other: the service's signed answer to this request, addressed back to
  // the session key that asked. The auth family verifies a proof bound to
  // its own `issuer` — the session key signs as *itself*
  // (`"session-key"`), not as a delegate for the session's subject (unlike
  // an ordinary authenticated call; see `trust-task.ts`'s `"session"`
  // signer). Mirrors the session-key binding `auth/authenticate/0.2`/`0.3`
  // established at login. No bearer: the refresh token in the payload is
  // the credential, and `request()` must not try to renew from inside a
  // renewal.
  const { trustTask } = await import("./trust-task");
  const reply = await trustTask<RefreshPayload, RefreshResponse>(
    REFRESH_TASK_URI,
    { refreshToken: refresh },
    { signer: "session-key", anonymous: true },
  );
  const nextAccess = reply?.tokens?.accessToken;
  const nextRefresh = reply?.tokens?.refreshToken;
  if (typeof nextAccess !== "string" || nextAccess === "") {
    throw new Error("auth/refresh answered without an access token");
  }
  setToken(nextAccess);
  if (typeof nextRefresh === "string") setRefreshToken(nextRefresh);
}

export function getAuthMethod(): AuthMethod | null {
  return authMethodMem;
}

export function setAuthMethod(method: AuthMethod): void {
  authMethodMem = method;
  persistSession();
}

export function clearToken(): void {
  announceSignOut(getSessionId());
  accessTokenMem = null;
  // Clear the renewal credential too: a refresh token outliving a logout
  // would leave the browser able to mint fresh access tokens.
  refreshTokenMem = null;
  authMethodMem = null;
  // A restore that is still in flight (or has not run yet) must not resurrect
  // what logout just cleared, and a repeat logout must not resurrect the
  // record if this delete races the last renewal's persist — so mark the
  // cache settled and overwrite the IDB record, rather than leaving it to
  // `persistSession()`'s put racing `idbDeleteSession()` below.
  sessionRestored = true;
  idbDeleteSession().catch((e) => {
    console.warn("session: IDB clear failed", e);
  });
  // Drop the session keypair from both memory and IndexedDB.
  // Fire-and-forget; logout shouldn't block on storage.
  clearSessionKeypair();
}

/** The access token's claims, read without verification. See the module doc. */
function tokenClaims(): Record<string, unknown> | null {
  return decodeJwtPayload(getToken());
}

/**
 * The DID the current bearer session authenticated — the access token's
 * `sub`. Every signed document names it as its `issuer`.
 */
export function getSessionSubjectDid(): string | null {
  const sub = tokenClaims()?.sub;
  return typeof sub === "string" ? sub : null;
}

/** The session the access token belongs to — what a step-up elevates. */
export function getSessionId(): string | null {
  const sid = tokenClaims()?.session_id;
  return typeof sid === "string" && sid.length > 0 ? sid : null;
}

// ---------------------------------------------------------------------------
// Sign-out across tabs
// ---------------------------------------------------------------------------

/** The `BroadcastChannel` a sign-out is announced on. */
const SIGN_OUT_CHANNEL = "did-hosting-ui-session";

type SignOutMessage = { type: "signed-out"; sessionId: string | null };

/** Tell the other tabs of this origin that `sessionId` has signed out. Not
 *  delivered to the posting channel itself. No-op where `BroadcastChannel`
 *  does not exist (native builds). */
function announceSignOut(sessionId: string | null): void {
  if (typeof BroadcastChannel === "undefined") return;
  try {
    const channel = new BroadcastChannel(SIGN_OUT_CHANNEL);
    const message: SignOutMessage = { type: "signed-out", sessionId };
    channel.postMessage(message);
    channel.close();
  } catch {
    // Best effort: the other tabs still find out on their next request.
  }
}

/**
 * Drop this tab's copy of the session when another tab signs it out, then
 * call `onSignedOut`. A message for a different session (this tab signed in
 * again since) is ignored. Storage is not touched: the tab that signed out
 * has already cleared it. Returns a function that stops listening.
 */
export function listenForSignOut(onSignedOut: () => void): () => void {
  if (typeof BroadcastChannel === "undefined") return () => {};
  let channel: BroadcastChannel;
  try {
    channel = new BroadcastChannel(SIGN_OUT_CHANNEL);
  } catch {
    return () => {};
  }
  channel.onmessage = (event: MessageEvent) => {
    const message = event.data as Partial<SignOutMessage> | null;
    if (message?.type !== "signed-out") return;
    if (accessTokenMem === null) return;
    const mine = getSessionId();
    if (message.sessionId && mine && message.sessionId !== mine) return;
    accessTokenMem = null;
    refreshTokenMem = null;
    authMethodMem = null;
    sessionRestored = true;
    forgetSessionKeypair();
    onSignedOut();
  };
  return () => channel.close();
}
