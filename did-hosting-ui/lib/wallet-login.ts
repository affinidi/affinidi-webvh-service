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
 * `id_token` and the page posts it to `/auth/` itself. It binds the same key
 * there instead, as `session_pubkey_b58btc` — see
 * {@link authenticateIdTokenBindingSessionKey}.
 *
 * Kept free of `react-native` so the test runner can reach it; `wallet.ts`
 * re-exports the entry point.
 */

import { clearSessionKeypair, generateSessionKeypair } from "./session-key";

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

/** The canonical `/auth/` response: `{ session, tokens }`, both camelCase. */
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

/**
 * Post a proxy login's `id_token` to `{apiBase}/auth/`, binding a fresh
 * session key to the new session.
 *
 * The persona's own key lives at the VTA, so without a session key every call
 * the session makes is signed through the wallet's `signTrustTask` — which
 * asks the human each time, by design, and a page load fires several at once.
 * The route refuses a key it cannot bind rather than dropping it, so a success
 * means the key is bound. On any failure the key pair is dropped, as in
 * {@link loginBindingSessionKey}.
 *
 * Returns the envelope sent, for the login screen's walkthrough.
 */
export async function authenticateIdTokenBindingSessionKey(
  apiBase: string,
  args: { idToken: string; sessionId: string; typeUri: string },
  fetchFn: typeof fetch = fetch,
): Promise<{ response: IdTokenAuthResponse; sent: Record<string, unknown> }> {
  const { pubkeyMultikey } = await generateSessionKeypair();
  const sent = {
    type: args.typeUri,
    payload: {
      id_token: args.idToken,
      // Snake_case: `AuthenticatePayload` has no `rename_all`.
      session_id: args.sessionId,
      session_pubkey_b58btc: pubkeyMultikey,
    },
  };
  try {
    const res = await fetchFn(`${apiBase}/auth/`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sent),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`/auth/ failed (${res.status}): ${text}`);
    }
    const response = (await res.json()) as IdTokenAuthResponse;
    if (!response.tokens?.accessToken) {
      throw new Error(
        `/auth/: missing tokens.accessToken in response — got ${JSON.stringify(response).slice(0, 200)}`,
      );
    }
    return { response, sent };
  } catch (err) {
    clearSessionKeypair();
    throw err;
  }
}
