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
