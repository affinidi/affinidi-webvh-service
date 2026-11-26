/**
 * Adding a passkey to yourself: the console's side of
 * `auth/passkey/enroll/{start,finish}/0.2` — a backup authenticator for a
 * subject who is already signed in, with no invite.
 *
 * 1. {@link startAddPasskey} opens the registration. When the caller already
 *    holds a login passkey the response also carries a user-verification
 *    request over those, so a stolen session alone cannot add an
 *    authenticator. A *first* login passkey needs a stepped-up session
 *    instead (the API steps a wallet session up and retries).
 * 2. {@link completeAddPasskey} runs the WebAuthn ceremonies — an existing
 *    passkey first, where asked, then the new one — and sends both results.
 *
 * WebAuthn is injected so the flow can be exercised without a browser.
 */

import { api, needsStepUp, type EnrollFinishResponse, type EnrollStartResponse } from "./api";
import type { WebAuthnCeremonies } from "./enrol-flow";
import { isRejection } from "./trust-task";

/** A refusal worded for the person adding the passkey. */
export class AddPasskeyError extends Error {}

/** The longest label the console sends. The spec allows 256; the control
 *  plane's schema check is what holds a direct caller to that. */
export const MAX_DEVICE_LABEL = 64;

/** A label as sent: trimmed, absent when blank, refused when too long. */
function normaliseLabel(label: string | undefined): string | undefined {
  const trimmed = label?.trim();
  if (!trimmed) return undefined;
  if ([...trimmed].length > MAX_DEVICE_LABEL) {
    throw new AddPasskeyError(`Keep the label to ${MAX_DEVICE_LABEL} characters or fewer.`);
  }
  return trimmed;
}

/** A label for display: one line, clipped. */
export function displayLabel(label: string): string {
  const flat = label.replace(/\s+/g, " ").trim();
  const chars = [...flat];
  return chars.length > MAX_DEVICE_LABEL ? `${chars.slice(0, MAX_DEVICE_LABEL).join("")}…` : flat;
}

/** Open a registration for another login passkey of the caller's own. */
export async function startAddPasskey(deviceLabel?: string): Promise<EnrollStartResponse> {
  try {
    return await api.enrollStart(normaliseLabel(deviceLabel));
  } catch (e) {
    if (isRejection(e, "maxCredentialsReached")) {
      throw new AddPasskeyError(
        "You already have the most passkeys this console allows. Revoke one you no longer use first.",
      );
    }
    if (isRejection(e, "reauthUnavailable")) {
      throw new AddPasskeyError(
        "This console cannot re-verify you with a passkey you already hold, so it can't add another. Ask an administrator.",
      );
    }
    if (isRejection(e, "enrollmentNotSupported")) {
      throw new AddPasskeyError("This control plane does not enrol passkeys.");
    }
    throw e;
  }
}

/** Create the passkey (proving an existing one first, where asked) and bind it. */
export async function completeAddPasskey(
  start: EnrollStartResponse,
  webauthn: WebAuthnCeremonies,
  deviceLabel?: string,
): Promise<EnrollFinishResponse> {
  const label = normaliseLabel(deviceLabel);
  const uvCredential = start.uvOptions
    ? await webauthn.get({ publicKey: structuredClone(start.uvOptions) })
    : undefined;
  const credential = await webauthn.create({ publicKey: structuredClone(start.options) });
  try {
    return await api.enrollFinish(start.enrollmentId, credential, uvCredential, label);
  } catch (e) {
    if (isRejection(e, "enrollmentExpired") || isRejection(e, "enrollmentNotFound")) {
      throw new AddPasskeyError("This registration timed out or was replaced. Start again.");
    }
    if (isRejection(e, "subjectMismatch")) {
      throw new AddPasskeyError(
        "Your session changed while the passkey was being added. Start again.",
      );
    }
    if (isRejection(e, "attestationInvalid")) {
      throw new AddPasskeyError(
        "That passkey could not be registered — it may already be registered here. Try a different authenticator.",
      );
    }
    // The control plane answers a failed check of the existing passkey as a
    // plain `permissionDenied`; a step-up refusal is reported as itself.
    if (uvCredential && isRejection(e, "permissionDenied") && !needsStepUp(e)) {
      throw new AddPasskeyError(
        "Your existing passkey did not confirm this. Retry with a passkey you already use here.",
      );
    }
    throw e;
  }
}
