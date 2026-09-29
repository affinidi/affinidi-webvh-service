/**
 * The browser's session state: the bearer tokens, which login produced them,
 * and what the access token says about the session.
 *
 * Nothing here is trusted for authorisation — the control plane verifies the
 * token and the document proof on every request. The UI reads the claims only
 * to name its own `issuer` and the session it asks to step up.
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

const TOKEN_KEY = "webvh_token";
const REFRESH_TOKEN_KEY = "webvh_refresh_token";

/** Which auth path produced the current session. Passkey, wallet holder and
 *  wallet proxy logins all bind the browser's session keypair, which then
 *  signs trust tasks; a session whose key this browser no longer holds ends.
 *  Only step-up branches on this: a wallet session steps up through the
 *  wallet. */
export type AuthMethod = "passkey" | "wallet";
const AUTH_METHOD_KEY = "webvh_auth_method";

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // ignore in non-browser contexts
  }
}

/// The refresh token, which login used to hand us and we used to discard.
///
/// Without it the console could not renew: the access token is a fixed
/// 15-minute JWT, nothing extended it, and the first sign of expiry was a
/// request failing. It lives beside the access token in `localStorage` —
/// no worse a place, since a reader of one already has the other.
export function getRefreshToken(): string | null {
  try {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setRefreshToken(token: string | null): void {
  try {
    if (token === null) localStorage.removeItem(REFRESH_TOKEN_KEY);
    else localStorage.setItem(REFRESH_TOKEN_KEY, token);
  } catch {
    // ignore in non-browser contexts
  }
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
  try {
    const v = localStorage.getItem(AUTH_METHOD_KEY);
    return v === "passkey" || v === "wallet" ? v : null;
  } catch {
    return null;
  }
}

export function setAuthMethod(method: AuthMethod): void {
  try {
    localStorage.setItem(AUTH_METHOD_KEY, method);
  } catch {
    // ignore
  }
}

export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
    // Clear the renewal credential too: a refresh token outliving a logout
    // would leave the browser able to mint fresh access tokens.
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(AUTH_METHOD_KEY);
  } catch {
    // ignore
  }
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
