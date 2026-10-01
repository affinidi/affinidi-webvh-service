/**
 * Revoking a passkey: the console's side of
 * `auth/passkey/revoke/{start,finish}`.
 *
 * Revoke is a re-authentication ceremony, not a bare delete: `start` opens a
 * fresh WebAuthn user-verification challenge over the *caller's own*
 * credentials (the person acting proves they are present, whoever owns the
 * credential being revoked); `finish` verifies that assertion and only then
 * unbinds the named credential. The flow is two steps for the same reason
 * enrolment's is — so the page can show what's about to be revoked before the
 * browser runs a ceremony — but here neither step creates anything: `start`
 * answers a challenge, `finish` answers it back.
 *
 * WebAuthn is injected so the flow can be exercised without a browser.
 */

import {
  api,
  type RevokePasskeyFinishResponse,
  type RevokePasskeyStartResponse,
} from "./api";
import { isRejection } from "./trust-task";

/** `navigator.credentials.get`, over `{ publicKey }` — the one ceremony a
 *  revocation runs (there is nothing to create). */
export interface WebAuthnAssertion {
  get: (options: { publicKey: unknown }) => Promise<any>;
}

/** A refusal worded for whoever is revoking, not the operator. */
export class RevocationError extends Error {}

/**
 * Open a revocation for `credentialId` — the caller's own, or, for an
 * administrator, `subject`'s.
 */
export async function startRevocation(
  credentialId: string,
  subject?: string,
): Promise<RevokePasskeyStartResponse> {
  try {
    return await api.revokePasskeyStart(credentialId, subject);
  } catch (e) {
    if (isRejection(e, "lastCredential")) {
      throw new RevocationError(
        "This is the only sign-in passkey left; it can't be revoked this way. Enrol a replacement first.",
      );
    }
    if (isRejection(e, "reauthUnavailable")) {
      throw new RevocationError(
        "You have no passkey this console can re-verify you with, so a revocation can't be started.",
      );
    }
    if (isRejection(e, "notAuthorized")) {
      throw new RevocationError("You may not revoke that subject's passkey.");
    }
    if (isRejection(e, "credentialNotFound")) {
      throw new RevocationError("That passkey is already gone.");
    }
    throw e;
  }
}

/** Run the user-verification ceremony `start` opened and complete the
 *  revocation. */
export async function completeRevocation(
  start: RevokePasskeyStartResponse,
  webauthn: WebAuthnAssertion,
): Promise<RevokePasskeyFinishResponse> {
  const uvCredential = await webauthn.get({
    publicKey: structuredClone(start.uvOptions),
  });
  try {
    return await api.revokePasskeyFinish(start.revocationId, uvCredential);
  } catch (e) {
    if (
      isRejection(e, "revocationExpired") ||
      isRejection(e, "revocationNotFound")
    ) {
      throw new RevocationError(
        "This revocation timed out or was replaced. Start again.",
      );
    }
    if (isRejection(e, "userVerificationFailed")) {
      throw new RevocationError(
        "That passkey did not confirm this. Retry with a passkey you already use here.",
      );
    }
    if (isRejection(e, "lastCredential")) {
      throw new RevocationError(
        "This is now the only sign-in passkey left; it can't be revoked this way.",
      );
    }
    if (isRejection(e, "notAuthorized")) {
      throw new RevocationError(
        "Administrator standing was withdrawn before this could complete.",
      );
    }
    throw e;
  }
}
