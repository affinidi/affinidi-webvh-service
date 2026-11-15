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
 * session key. A step-up's decision still goes to the wallet
 * (`approveSessionStepUp`): the control plane never accepts a session key
 * where an `assertionMethod` approval is required. The wallet gets the
 * step-up's signed approve-request only, never the session's tokens.
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
 *
 * @deprecated Contract C7: the legacy SIOPv2 / `auth/authenticate` wallet
 * login. The default is wallet sign-in with a trigger link (`oob-sign-in.ts`).
 */

import { clearSessionKeypair, generateSessionKeypair } from "./session-key";
import { T } from "./task-types";
import { trustTask } from "./trust-task";
import type {
  Payload as AuthenticatePayload,
  Response as AuthenticateResponse,
} from "./trust-tasks/auth/authenticate/0.3/payload";

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
export type IdTokenAuthResponse = AuthenticateResponse;

const AUTH_AUTHENTICATE_V0_3 = T.authenticate;

/**
 * Wrap a proxy login's `id_token` as an `auth/authenticate/0.3` proxied
 * authenticate, sent through the console's Trust Task client
 * (`POST /api/trust-tasks`), and bind a fresh session key to the new session.
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
 * Going through `trustTask` (signer `"session-key"`, no bearer) means the
 * reply is checked like every other: the service's own signed answer to this
 * request, addressed back to the key that asked. A reply that is not is
 * refused before its tokens are used.
 *
 * The persona's own key lives at the VTA, so without a session key every call
 * the session makes would be signed through the wallet's `signTrustTask` —
 * which asks the human each time, by design, and a page load fires several at
 * once. The control plane refuses a key it cannot bind rather than dropping
 * it, so a success means the key is bound. On any failure the key pair is
 * dropped, as in {@link loginBindingSessionKey}.
 */
export async function authenticateIdTokenBindingSessionKey(args: {
  idToken: string;
  sessionId: string;
  challenge: string;
  principalDid: string;
}): Promise<IdTokenAuthResponse> {
  const { didKey } = await generateSessionKeypair();
  try {
    const response = await trustTask<AuthenticatePayload, AuthenticateResponse>(
      AUTH_AUTHENTICATE_V0_3,
      {
        challenge: args.challenge,
        sessionId: args.sessionId,
        principal: args.principalDid,
        delegationEvidence: {
          kind: "siopIdToken",
          credential: { idToken: args.idToken },
        },
        sessionKey: didKey,
      },
      { signer: "session-key", anonymous: true },
    );
    if (!response?.tokens?.accessToken) {
      throw new Error("auth/authenticate/0.3: the reply carries no access token");
    }
    return response;
  } catch (err) {
    clearSessionKeypair();
    throw err;
  }
}
