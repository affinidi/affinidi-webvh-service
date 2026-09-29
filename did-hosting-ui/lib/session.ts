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
 * way `session-key.ts` restores the signing keypair. Never `localStorage`:
 * it is a flat, synchronous, string-keyed object any script on the origin can
 * enumerate in one line (`Object.entries(localStorage)`), which is exactly
 * the shape a generic exfiltration payload greps for. IndexedDB holds the
 * same bytes but needs a targeted, asynchronous lookup, so it does not fall
 * to that class of blanket scrape — the same reasoning that already put the
 * session signing key there instead of `localStorage`.
 */

import {
  clearSessionKeypair,
  getSessionDidKey,
  hasSessionKeypair,
  restoreSessionKeypair,
  signEnvelope,
} from "./session-key";
// `trust-task.ts` imports `clearToken`/`getSessionSubjectDid` from this
// module, so a static top-level import back the other way is a genuine
// cycle, not one that "resolves fine": `trust-task.ts` declares `class
// TrustTaskRejection extends ApiError` at module-eval time, and whichever of
// the two modules a caller reaches first leaves the other only partially
// evaluated when that class body runs — `ApiError` is still unbound and the
// `extends` throws. A dynamic `import()` inside `renewIfNeeded` below defers
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
    req.onblocked = () =>
      reject(new Error("indexedDB.open blocked by an older connection"));
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
    // eslint-disable-next-line no-console
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
      // eslint-disable-next-line no-console
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
}

const REFRESH_TASK_URI = "https://trusttasks.org/spec/auth/refresh/0.2";

/** Seconds since the epoch at which `token` expires, or null if unreadable. */
function tokenExpiry(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const exp = JSON.parse(atob(payload)).exp;
    return typeof exp === "number" ? exp : null;
  } catch {
    return null;
  }
}

/** Renew when the access token has this long or less to live. */
const RENEW_WITHIN_SECS = 60;
/** Floor between renewal attempts, so a failing one cannot spin. */
const MIN_RETRY_GAP_MS = 5_000;

let renewInFlight: Promise<void> | null = null;
let lastRenewAttemptMs = 0;

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
 * `absoluteExpiresAt` — that one only a fresh sign-in can lift. Never
 * throws: a failed renewal leaves the session alone and the caller's own
 * request reports the failure.
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
  if (Date.now() - lastRenewAttemptMs < MIN_RETRY_GAP_MS) return;
  lastRenewAttemptMs = Date.now();

  renewInFlight = (async () => {
    try {
      // After a reload the key is only in IndexedDB. Without restoring it
      // first, the refresh would go out unsigned and be refused — every
      // login this UI offers binds one, so in practice this always signs.
      if (!hasSessionKeypair()) {
        await restoreSessionKeypair();
      }
      if (!hasSessionKeypair()) return;

      const { TRUST_TASKS_PATH, getServiceInfo } = await import("./trust-task");
      const { serviceDid } = await getServiceInfo();
      let envelope: Record<string, unknown> = {
        type: REFRESH_TASK_URI,
        id: crypto.randomUUID(),
        recipient: serviceDid,
        issuedAt: new Date().toISOString(),
        // The auth family verifies a proof bound to its own `issuer` — the
        // session key signs as *itself*, not as a delegate for the
        // session's subject (unlike an ordinary authenticated call; see
        // `trust-task.ts`'s `"session"` signer). Mirrors the session-key
        // binding `auth/authenticate/0.2`/`0.3` established at login.
        issuer: getSessionDidKey(),
        payload: { refreshToken: refresh },
      };
      envelope = await signEnvelope(envelope);
      const res = await fetch(TRUST_TASKS_PATH, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      });
      if (!res.ok) return;
      const body = await res.json();
      const nextAccess = body?.payload?.tokens?.accessToken;
      const nextRefresh = body?.payload?.tokens?.refreshToken;
      if (typeof nextAccess === "string") setToken(nextAccess);
      if (typeof nextRefresh === "string") setRefreshToken(nextRefresh);
    } catch {
      // Swallowed by design — see the doc comment.
    } finally {
      renewInFlight = null;
    }
  })();
  return renewInFlight;
}

export function getAuthMethod(): AuthMethod | null {
  return authMethodMem;
}

export function setAuthMethod(method: AuthMethod): void {
  authMethodMem = method;
  persistSession();
}

export function clearToken(): void {
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
    // eslint-disable-next-line no-console
    console.warn("session: IDB clear failed", e);
  });
  // Drop the session keypair from both memory and IndexedDB.
  // Fire-and-forget; logout shouldn't block on storage.
  clearSessionKeypair();
}

/** The access token's claims, read without verification. See the module doc. */
function tokenClaims(): Record<string, unknown> | null {
  const token = getToken();
  const payload = token?.split(".")[1];
  if (!payload) return null;
  try {
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const claims = JSON.parse(atob(padded));
    return claims && typeof claims === "object" ? claims : null;
  } catch {
    return null;
  }
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
