/**
 * Wallet login that binds this browser's session key (`auth/authenticate/0.2`).
 *
 * The passkey path already signs console calls with a non-extractable session
 * key generated at login (`session-key.ts`). A wallet login used to have
 * nothing like it, so every signed call was another wallet prompt. This reuses
 * the same key store:
 *
 *  1. Generate a fresh non-extractable Ed25519 key pair for this login.
 *  2. Ask the wallet to sign in with its `did:key` as `sessionKey`. The wallet
 *     puts it inside the authenticate document the subject signs, so the
 *     control plane binds it to the new session.
 *  3. Require the wallet to report the key as bound. The wallet fails a login
 *     the control plane did not bind, but a wallet too old to know about
 *     session keys would ignore the parameter and sign in without one.
 *
 * From then on `trust-task.ts` signs this session's ordinary calls with the
 * session key. Step-up still goes to the wallet (`stepUpVta`): the control
 * plane never accepts a session key where an `assertionMethod` approval is
 * required.
 *
 * A proxy login cannot go through `wallet.login`: the VTA mints the persona's
 * `id_token`, and the page wraps it as `auth/authenticate/0.3` proxied
 * `delegationEvidence` — see {@link authenticateIdTokenBindingSessionKey}.
 * The same fresh key both signs that document (as its own `issuer` — the
 * *delegate*, not the principal) and is named as `sessionKey`, so it is what
 * the control plane binds to the new session too.
 *
 * Kept free of `react-native` so the test runner can reach it; `wallet.ts`
 * re-exports the entry point.
 */

import { clearSessionKeypair, generateSessionKeypair, signEnvelope } from "./session-key";

export interface VtaWalletLoginParams {
  rpDid: string;
  baseUrl: string;
  /** A `did:key` for the control plane to bind to the session. */
  sessionKey?: string;
}

export interface VtaWalletLoginResult {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  holderDid: string;
  /** The `did:key` the control plane bound, when one was requested. */
  sessionKey?: string;
}

export interface SessionKeyLoginWallet {
  login(params: VtaWalletLoginParams): Promise<VtaWalletLoginResult>;
}

/**
 * Sign in through `wallet`, binding a fresh session key to the new session.
 *
 * On any failure the key pair is dropped, so a key no session was bound to
 * cannot linger and be used to sign later calls.
 */
export async function loginBindingSessionKey(
  wallet: SessionKeyLoginWallet,
  params: { rpDid: string; baseUrl: string },
): Promise<VtaWalletLoginResult> {
  const { didKey } = await generateSessionKeypair();
  try {
    const result = await wallet.login({ ...params, sessionKey: didKey });
    if (result.sessionKey !== didKey) {
      throw new Error(
        "The wallet signed in without binding this browser's session key. Update the VTI Wallet extension and sign in again.",
      );
    }
    return result;
  } catch (err) {
    clearSessionKeypair();
    throw err;
  }
}

/** The `auth/authenticate/0.3` response payload: `{ session, tokens }`, both
 *  camelCase. */
export interface IdTokenAuthResponse {
  session: { id: string; subject: string; issuedAt: string; expiresAt: string };
  tokens: {
    accessToken: string;
    refreshToken?: string;
    tokenType: string;
    expiresIn: number;
    refreshExpiresIn?: number;
  };
}

const AUTH_AUTHENTICATE_V0_3 = "https://trusttasks.org/spec/auth/authenticate/0.3";

/**
 * Wrap a proxy login's `id_token` as an `auth/authenticate/0.3` proxied
 * authenticate, sent to `{apiBase}/trust-tasks`, and bind a fresh session key
 * to the new session.
 *
 * A fresh Ed25519 `did:key` plays two roles in the one document: it is the
 * document's own `issuer` (the *delegate* the proxied form names, verified by
 * its `proof` exactly as any other authenticate signer) and, named again as
 * `payload.sessionKey`, the key the control plane binds to the session this
 * creates — so no separate wallet prompt signs the console's later calls. The
 * `id_token` itself becomes `delegationEvidence` (`kind: "siopIdToken"`): the
 * control plane verifies it independently against the principal's own DID
 * document, checks its `nonce` against this same `challenge`, and only then
 * honors `principal`.
 *
 * The persona's own key lives at the VTA, so without a session key every call
 * the session makes would be signed through the wallet's `signTrustTask` —
 * which asks the human each time, by design, and a page load fires several at
 * once. The control plane refuses a key it cannot bind rather than dropping
 * it, so a success means the key is bound. On any failure the key pair is
 * dropped, as in {@link loginBindingSessionKey}.
 *
 * Returns the envelope sent, for the login screen's walkthrough.
 */
export async function authenticateIdTokenBindingSessionKey(
  apiBase: string,
  args: { idToken: string; sessionId: string; challenge: string; principalDid: string; rpDid: string },
  fetchFn: typeof fetch = fetch,
): Promise<{ response: IdTokenAuthResponse; sent: Record<string, unknown> }> {
  const { didKey } = await generateSessionKeypair();
  let sent: Record<string, unknown> = {
    id: cryptoRandomUuid(),
    type: AUTH_AUTHENTICATE_V0_3,
    issuer: didKey,
    recipient: args.rpDid,
    issuedAt: new Date().toISOString(),
    payload: {
      challenge: args.challenge,
      sessionId: args.sessionId,
      principal: args.principalDid,
      delegationEvidence: {
        kind: "siopIdToken",
        credential: { idToken: args.idToken },
      },
      sessionKey: didKey,
    },
  };
  try {
    sent = await signEnvelope(sent);
    const res = await fetchFn(`${apiBase}/trust-tasks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sent),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`auth/authenticate/0.3 failed (${res.status}): ${text}`);
    }
    const reply = (await res.json()) as { payload?: IdTokenAuthResponse };
    const response = reply?.payload;
    if (!response?.tokens?.accessToken) {
      throw new Error(
        `auth/authenticate/0.3: missing payload.tokens.accessToken in response — got ${JSON.stringify(reply).slice(0, 200)}`,
      );
    }
    return { response, sent };
  } catch (err) {
    clearSessionKeypair();
    throw err;
  }
}

/** Browser-safe UUIDv4. Falls back to a polyfill where `crypto.randomUUID`
 *  isn't available. Duplicated from `trust-task.ts` rather than imported: this
 *  module is intentionally free of the rest of that file's dependencies (see
 *  the module doc). */
function cryptoRandomUuid(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex
    .slice(6, 8)
    .join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}
