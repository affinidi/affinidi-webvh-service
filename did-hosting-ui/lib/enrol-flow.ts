/**
 * Redeeming a passkey enrolment invite: the console's side of
 * `auth/passkey/enroll/redeem/{start,finish}`.
 *
 * The invite URL carries the token; the claim code arrives by a different
 * channel and is typed here. The flow is two steps so the page can show whose
 * passkey this will be, and what it may do, before the browser creates it:
 *
 * 1. {@link startRedemption} presents both halves and gets the registration
 *    the invite authorises — and, when the subject already holds passkeys of
 *    the invite's purpose, a user-verification request over them;
 * 2. {@link completeRedemption} runs the WebAuthn ceremonies (the browser's
 *    own, the one thing here that is not a Trust Task) and returns their
 *    results in the finish.
 *
 * WebAuthn is injected so the flow can be exercised without a browser.
 */

import { api, type RedeemFinishResponse, type RedeemStartResponse } from "./api";
import { isRejection } from "./trust-task";

/** `navigator.credentials.create` / `.get`, over `{ publicKey }`. */
export interface WebAuthnCeremonies {
  create: (options: { publicKey: unknown }) => Promise<any>;
  get: (options: { publicKey: unknown }) => Promise<any>;
}

/** A refusal worded for the invitee, not the operator. */
export class RedemptionError extends Error {}

/** Present the token and claim code; answer the ceremony to confirm. */
export async function startRedemption(
  token: string,
  claimCode: string,
): Promise<RedeemStartResponse> {
  if (!token) throw new RedemptionError("This link has no invite token.");
  if (!claimCode.trim()) throw new RedemptionError("Enter the claim code you were sent.");
  try {
    return await api.redeemStart(token, claimCode.trim());
  } catch (e) {
    if (isRejection(e, "tooManyAttempts")) {
      throw new RedemptionError(
        "Too many wrong claim codes: this invite has been cancelled. Ask for a new one.",
      );
    }
    if (isRejection(e, "inviteInvalid")) {
      throw new RedemptionError(
        "That invite and claim code do not match an open invite. Check the code, or ask for a new invite if it has expired or been used.",
      );
    }
    throw e;
  }
}

/** Create the passkey (and, where asked, prove an existing one) and bind it. */
export async function completeRedemption(
  start: RedeemStartResponse,
  webauthn: WebAuthnCeremonies,
  deviceLabel?: string,
): Promise<RedeemFinishResponse> {
  // An existing passkey of the same purpose authorises the new one first, so
  // a stolen invite alone cannot add an authenticator to an enrolled subject.
  const uvCredential = start.uvOptions
    ? await webauthn.get({ publicKey: structuredClone(start.uvOptions) })
    : undefined;
  const credential = await webauthn.create({ publicKey: structuredClone(start.options) });
  try {
    return await api.redeemFinish(
      start.enrollmentId,
      credential,
      uvCredential,
      deviceLabel?.trim() || undefined,
    );
  } catch (e) {
    if (isRejection(e, "enrollmentExpired") || isRejection(e, "enrollmentNotFound")) {
      throw new RedemptionError(
        "This registration timed out or was replaced. Enter the claim code again to retry.",
      );
    }
    if (isRejection(e, "userVerificationFailed")) {
      throw new RedemptionError(
        "Your existing passkey did not confirm this. Retry with a passkey you already use here.",
      );
    }
    throw e;
  }
}

/** What a purpose means, for the confirmation screen. */
export function describePurpose(purpose: string): string {
  return purpose === "stepUp"
    ? "a step-up passkey: it confirms sensitive actions, and never signs you in"
    : "a sign-in passkey for this console";
}
