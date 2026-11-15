/**
 * Sessions and passkeys: sign-out, step-up, passkey login, enrolment invites
 * and passkey management.
 */

import type * as LoginStart from "../trust-tasks/auth/passkey/login/start/0.2/payload";
import type * as LoginFinish from "../trust-tasks/auth/passkey/login/finish/0.2/payload";
import type * as Invite from "../trust-tasks/auth/passkey/enroll/invite/0.3/payload";
import type * as RedeemStart from "../trust-tasks/auth/passkey/enroll/redeem/start/0.1/payload";
import type * as RedeemFinish from "../trust-tasks/auth/passkey/enroll/redeem/finish/0.1/payload";
import type * as InviteList from "../trust-tasks/auth/passkey/enroll/invite/list/0.1/payload";
import type * as InviteUpdate from "../trust-tasks/auth/passkey/enroll/invite/update/0.1/payload";
import type * as InviteRevoke from "../trust-tasks/auth/passkey/enroll/invite/revoke/0.1/payload";
import type * as PasskeyList from "../trust-tasks/auth/passkey/list/0.1/payload";
import type * as PasskeyAdminList from "../trust-tasks/auth/passkey/admin-list/0.1/payload";
import type * as PasskeyRevokeStart from "../trust-tasks/auth/passkey/revoke/start/0.2/payload";
import type * as PasskeyRevokeFinish from "../trust-tasks/auth/passkey/revoke/finish/0.2/payload";
import type * as RevokeSession from "../trust-tasks/auth/revoke-session/0.2/payload";
import type * as StepUpStart from "../trust-tasks/auth/step-up/start/0.2/payload";
import type * as StepUpApprove from "../trust-tasks/auth/step-up/approve-response/0.7/payload";
import { ApiError } from "../http";
import { STEP_UP_GUIDANCE } from "../errors";
import {
  clearToken,
  getAuthMethod,
  getRefreshToken,
  getSessionId,
  getToken,
  renewSessionNow,
  restoreSession,
} from "../session";
import { hasSessionKeypair, restoreSessionKeypair } from "../session-key";
import {
  getServiceInfo,
  isRejection,
  sendSignedTrustTask,
  trustTask,
  type TrustTaskDocument,
} from "../trust-task";
import { inviteFromWire, passkeyCredentialFromWire } from "../wire";
import { T } from "./tasks";
import type {
  CreateInviteResponse,
  InviteListItem,
  InviteListResponse,
  InvitePurpose,
  LoginStartResponse,
  LoginTokens,
  PasskeyCredential,
  RedeemFinishResponse,
  RedeemStartResponse,
  RevokePasskeyFinishResponse,
  RevokePasskeyStartResponse,
  Role,
} from "./types";

/**
 * Whether `e` asks for a stepped-up session: the declared `stepUpRequired`
 * where a task declares it, else `permissionDenied` whose message is the
 * control plane's `step_up_required` class.
 */
export function needsStepUp(e: unknown): boolean {
  return (
    isRejection(e, "stepUpRequired") ||
    (isRejection(e, "permissionDenied") && e.payload.message === "step_up_required")
  );
}

/**
 * Run `send`, and when the control plane answers that it needs a stepped-up
 * session, step this session up (`authApi.stepUp`) and run it once more.
 *
 * The control plane asks for one on its destructive and privilege-raising
 * tasks when they come from a session: purging a domain (and its content on
 * one edge), deleting a DID, retiring an identity generation, issuing an
 * enrolment invite, and making a subject an administrator or service account.
 * A passkey login is already stepped up, so it never sees the refusal.
 */
export async function withStepUp<R>(send: () => Promise<R>): Promise<R> {
  try {
    return await send();
  } catch (e) {
    if (!needsStepUp(e)) throw e;
    await authApi.stepUp();
    return send();
  }
}

export const authApi = {
  /**
   * Sign out: end this session at the control plane, then forget it here.
   *
   * Clearing the browser's copy alone would leave the session, and any session
   * key bound to it, live until it expires. `auth/revoke-session` deletes the
   * row, and every later request made with the token or the key is refused.
   * It is signed with the session key, so signing out never prompts the wallet.
   * A session with no bound key (a proxy login) is cleared locally only,
   * because revoking it would cost a wallet prompt to sign out.
   *
   * Best effort. A failed revoke still signs this browser out; the session
   * then lapses at its expiry.
   */
  logout: async (): Promise<void> => {
    // The token/session cache lives in memory, restored from IndexedDB — a
    // logout clicked before anything else has read the session must still
    // see it.
    await restoreSession();
    const token = getToken();
    const sessionId = getSessionId();
    try {
      if (!hasSessionKeypair()) await restoreSessionKeypair();
      if (sessionId && hasSessionKeypair()) {
        await trustTask<RevokeSession.Payload, RevokeSession.Response>(T.revokeSession, {
          sessionId,
          reason: "logout",
        });
      }
    } catch {
      // Signed out locally regardless; see above.
    } finally {
      // Unless a new sign-in has replaced this session while the revoke was
      // in flight: clearing then would drop the new session's token and key.
      if (getToken() === token) clearToken();
    }
  },

  /**
   * Raise this session to `aal2` through the wallet, without handing the
   * wallet any of the session's tokens:
   *
   * 1. The console opens the step-up itself: `auth/step-up/start`, signed by
   *    the session key bound at login, for this session. The control plane
   *    answers with its signed `approve-request` — a single-use challenge
   *    bound to this session and its subject, that lapses on its own.
   * 2. The wallet gets that approve-request and nothing else. It verifies it,
   *    asks the user, and returns its `approve-response`, signed as the
   *    subject (`approveSessionStepUp`). A session key may never sign an
   *    approval, so this is the one step the wallet is needed for.
   * 3. The console sends the decision. The control plane checks it answers
   *    the pending challenge for this session, signed by its subject, and
   *    raises the session's level.
   * 4. The console renews the session with `auth/refresh`, signed by the
   *    session key with the refresh token held here, so the new tokens carry
   *    the raised level.
   *
   * Only a wallet session can do this; a passkey session is `aal2` from login.
   */
  stepUp: async (): Promise<void> => {
    await restoreSession();
    const wallet = typeof window !== "undefined" ? window.vtaWallet : undefined;
    const sessionId = getSessionId();
    if (getAuthMethod() !== "wallet" || !wallet?.approveSessionStepUp) {
      throw new ApiError(403, STEP_UP_GUIDANCE);
    }
    if (!getToken() || !getRefreshToken() || !sessionId) {
      throw new ApiError(401, "No session to step up — sign in again.");
    }
    const { serviceDid } = await getServiceInfo();

    const { approveRequest } = await trustTask<StepUpStart.Payload, StepUpStart.Response>(
      T.stepUpStart,
      { sessionId },
    );
    const challenge = approveRequest?.payload?.challenge;
    if (
      approveRequest?.type !== T.stepUpApproveRequest ||
      approveRequest.issuer !== serviceDid ||
      approveRequest.payload?.sessionId !== sessionId ||
      typeof challenge !== "string"
    ) {
      throw new ApiError(
        502,
        "the control plane answered the step-up with no request for this session",
      );
    }

    const { approveResponse } = await wallet.approveSessionStepUp({
      rpDid: serviceDid,
      approveRequest: approveRequest as unknown as Record<string, unknown>,
    });
    const decision = approveResponse as unknown as TrustTaskDocument<StepUpApprove.Payload>;
    if (
      decision?.type !== T.stepUpApproveResponse ||
      decision.recipient !== serviceDid ||
      decision.payload?.challenge !== challenge ||
      decision.payload?.sessionId !== sessionId ||
      !decision.proof
    ) {
      throw new ApiError(400, "the wallet did not answer this step-up");
    }
    if (decision.payload.decision !== "approved") {
      throw new ApiError(403, "The step-up was declined in the wallet.");
    }

    const ack = await sendSignedTrustTask<StepUpApprove.Response>(decision);
    if (ack.status !== "elevated") {
      throw new ApiError(403, `The control plane did not raise the session (${ack.status}).`);
    }
    try {
      await renewSessionNow();
    } catch (e) {
      throw new ApiError(401, e instanceof Error ? e.message : "could not renew the session");
    }
  },

  // ---- Passkey login (Trust Tasks) ----

  /**
   * Open a login ceremony. Sent anonymously: opening one authorises nothing.
   * With no `subject` the browser offers the passkeys it can find by itself;
   * naming one also lists that subject's credentials, for a security key
   * enrolled as non-discoverable.
   */
  passkeyLoginStart: async (subject?: string): Promise<LoginStartResponse> => {
    const r = await trustTask<LoginStart.Payload, LoginStart.Response>(
      T.loginStart,
      { purpose: "login", ...(subject ? { subject } : {}) },
      { signer: "none", anonymous: true },
    );
    return { authId: r.authId, options: r.options };
  },

  /**
   * Finish the ceremony. The document is signed by a fresh session key as its
   * own `did:key`; the control plane binds the new session to exactly that
   * key, so every later request in the session must be signed by it. The
   * private key never leaves this browser.
   */
  passkeyLoginFinish: async (
    authId: string,
    credential: LoginFinish.Payload["credential"],
  ): Promise<LoginTokens> => {
    const r = await trustTask<LoginFinish.Payload, LoginFinish.Response>(
      T.loginFinish,
      { authId, credential },
      { signer: "fresh-session-key", anonymous: true },
    );
    if (r.purpose !== "login" || !r.tokens) {
      throw new ApiError(502, "the control plane finished a login without issuing a session");
    }
    return { accessToken: r.tokens.accessToken, refreshToken: r.tokens.refreshToken ?? null };
  },

  // ---- Passkey enrolment (Trust Tasks) ----

  /**
   * Issue an invite (administrator). A `session` invite enrols a login passkey
   * with `role`; a `stepUp` invite a step-up-only passkey, which carries no
   * role and never signs in.
   */
  createInvite: async (
    did: string,
    role: Role,
    purpose: InvitePurpose = "session",
  ): Promise<CreateInviteResponse> => {
    // Issuing an invite needs a stepped-up session, like a purge.
    const send = () =>
      trustTask<Invite.Payload, Invite.Response>(T.invite, {
        subject: did,
        ...(purpose === "session" ? { role } : { purpose }),
      });
    const r = await withStepUp(send);
    return {
      inviteUrl: r.invite.url,
      claimCode: r.claimCode,
      subject: r.subject,
      purpose: r.purpose,
      expiresAt: Math.floor(Date.parse(r.expiresAt) / 1000),
    };
  },

  /**
   * Present an invite's token (from its URL) and its claim code (delivered
   * separately). Sent anonymously and unsigned: the invitee has no key the
   * control plane knows, and the two halves are the authorisation.
   */
  redeemStart: async (token: string, claimCode: string): Promise<RedeemStartResponse> =>
    trustTask<RedeemStart.Payload, RedeemStart.Response>(
      T.redeemStart,
      { token, claimCode },
      { signer: "none", anonymous: true },
    ),

  /** Bind the new passkey (and, where asked, prove an existing one). */
  redeemFinish: async (
    enrollmentId: string,
    credential: RedeemFinish.Payload["credential"],
    uvCredential?: RedeemFinish.Payload["uvCredential"],
    deviceLabel?: string,
  ): Promise<RedeemFinishResponse> =>
    trustTask<RedeemFinish.Payload, RedeemFinish.Response>(
      T.redeemFinish,
      {
        enrollmentId,
        credential,
        // Only the members given: an `undefined` member cannot be
        // canonicalised, and the spec reads an absent one as "none".
        ...(uvCredential ? { uvCredential } : {}),
        ...(deviceLabel ? { deviceLabel } : {}),
      },
      { signer: "none", anonymous: true },
    ),

  // ---- Enrolment invites (Trust Tasks) ----

  listInvites: async (): Promise<InviteListResponse> => {
    const r = await trustTask<InviteList.Payload, InviteList.Response>(T.inviteList, {});
    return { invites: r.invites.map(inviteFromWire) };
  },

  /** Change a pending invite's role, or push its expiry out. */
  updateInvite: async (
    inviteId: string,
    updates: { role?: Role; expiresAt?: string; extendBy?: number },
  ): Promise<InviteListItem> => {
    // Only the members actually given: a document carrying an `undefined`
    // member cannot be canonicalised for its proof, and the spec reads an
    // absent member as "unchanged".
    const r = await trustTask<InviteUpdate.Payload, InviteUpdate.Response>(T.inviteUpdate, {
      inviteId,
      ...(updates.role !== undefined ? { role: updates.role } : {}),
      ...(updates.expiresAt !== undefined ? { expiresAt: updates.expiresAt } : {}),
      ...(updates.extendBy !== undefined ? { extendBy: updates.extendBy } : {}),
    });
    return inviteFromWire(r.invite);
  },

  revokeInvite: async (inviteId: string): Promise<void> => {
    await trustTask<InviteRevoke.Payload, InviteRevoke.Response>(T.inviteRevoke, { inviteId });
  },

  // ---- Passkey management (Trust Tasks) ----

  /** The caller's own passkeys, of every purpose — the credential-management
   *  counterpart to the session list: this answers "what can sign me in?". */
  listPasskeys: async (): Promise<PasskeyCredential[]> => {
    const r = await trustTask<PasskeyList.Payload, PasskeyList.Response>(T.passkeyList, {});
    return r.credentials.map(passkeyCredentialFromWire);
  },

  /** An administrator's purpose-scoped read of one subject's passkeys —
   *  never the owner's own `listPasskeys`, which takes no subject. */
  adminListPasskeys: async (
    subject: string,
    purpose: InvitePurpose,
  ): Promise<PasskeyCredential[]> => {
    const r = await trustTask<PasskeyAdminList.Payload, PasskeyAdminList.Response>(
      T.passkeyAdminList,
      { subject, purpose },
    );
    return r.credentials.map(passkeyCredentialFromWire);
  },

  /**
   * Begin revoking a passkey — the caller's own, or, for an administrator,
   * `subject`'s. The response carries a fresh user-verification challenge
   * over the *caller's* own credentials: the person acting proves they are
   * present, whoever owns the credential being revoked. Nothing is removed
   * until `revokePasskeyFinish` presents that assertion.
   */
  revokePasskeyStart: async (
    credentialId: string,
    subject?: string,
  ): Promise<RevokePasskeyStartResponse> =>
    trustTask<PasskeyRevokeStart.Payload, PasskeyRevokeStart.Response>(T.passkeyRevokeStart, {
      credentialId,
      ...(subject ? { subject } : {}),
    }),

  /** Present the user-verification assertion `revokePasskeyStart` asked for. */
  revokePasskeyFinish: async (
    revocationId: string,
    uvCredential: PasskeyRevokeFinish.Payload["uvCredential"],
  ): Promise<RevokePasskeyFinishResponse> => {
    const r = await trustTask<PasskeyRevokeFinish.Payload, PasskeyRevokeFinish.Response>(
      T.passkeyRevokeFinish,
      { revocationId, uvCredential },
    );
    return {
      credentialId: r.credentialId,
      subject: r.subject,
      purpose: r.purpose,
      revokedAt: Math.floor(Date.parse(r.revokedAt) / 1000),
      remaining: r.remaining,
    };
  },
};
