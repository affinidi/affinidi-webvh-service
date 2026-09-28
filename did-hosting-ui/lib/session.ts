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
  hasSessionKeypair,
  restoreSessionKeypair,
  signEnvelope,
} from "./session-key";

const TOKEN_KEY = "webvh_token";
const REFRESH_TOKEN_KEY = "webvh_refresh_token";

/** Which auth path produced the current session. Both passkey and wallet
 *  holder logins bind the browser's session keypair, which then signs
 *  trust tasks. A `"wallet"` session with no bound key (a proxy login) falls
 *  back to `window.vtaWallet.signTrustTask`. */
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

const REFRESH_TASK_URI = "https://trusttasks.org/spec/auth/refresh/0.1";

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
 * The daemon refuses a renewal once the session has been idle past
 * `auth.admin_idle_timeout`, which is what stops this timer from keeping a
 * tab signed in forever. Never throws: a failed renewal leaves the session
 * alone and the caller's own request reports the failure.
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
      // Signed with the session keypair, not sent bare. The daemon binds a
      // REST refresh to the key this browser registered at login, so a
      // stolen refresh token alone will not rotate the session. The refresh
      // token is still what authorises it: the key proves this is the
      // browser that logged in, and cannot refresh anything on its own. A
      // session with no bound key (a proxy login, machine-to-machine) has
      // nothing to sign with and the daemon does not ask.
      let envelope: Record<string, unknown> = {
        type: REFRESH_TASK_URI,
        id: crypto.randomUUID(),
        payload: { refreshToken: refresh },
      };
      // After a reload the key is only in IndexedDB. Without restoring it
      // first, the refresh would go out unsigned and be refused.
      if (!hasSessionKeypair()) {
        await restoreSessionKeypair();
      }
      if (hasSessionKeypair()) {
        envelope = await signEnvelope(envelope);
      }
      const res = await fetch("/api/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      });
      if (!res.ok) return;
      const body = await res.json();
      const nextAccess = body?.access_token ?? body?.tokens?.accessToken;
      const nextRefresh = body?.refresh_token ?? body?.tokens?.refreshToken;
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

/** DID the wallet-authenticated session is bound to. Set by the
 *  proxy-login flow to the vault entry's `principalDid`; the wallet's
 *  holder-login flow leaves this unset.
 *
 *  Trust-task signing reads this: when set, the wallet's
 *  `signTrustTask({ asDid })` extension routes via
 *  `vault/sign-trust-task/0.1` so the proof's `verificationMethod`
 *  matches the session's authenticated DID at the server. Without it,
 *  the wallet falls back to holder-signing and the server rejects with
 *  `proof_invalid: proof verificationMethod DID does not match the
 *  authenticated caller` (which is how this discriminator got
 *  motivated). */
const SESSION_PRINCIPAL_DID_KEY = "webvh_session_principal_did";

export function getSessionPrincipalDid(): string | null {
  try {
    return localStorage.getItem(SESSION_PRINCIPAL_DID_KEY);
  } catch {
    return null;
  }
}

export function setSessionPrincipalDid(did: string): void {
  try {
    localStorage.setItem(SESSION_PRINCIPAL_DID_KEY, did);
  } catch {
    // ignore
  }
}

export function clearSessionPrincipalDid(): void {
  try {
    localStorage.removeItem(SESSION_PRINCIPAL_DID_KEY);
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
    localStorage.removeItem(SESSION_PRINCIPAL_DID_KEY);
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
