/**
 * What to tell the operator about a caught value — in one place.
 *
 * Every `catch` in the console catches `unknown`: a Trust-Task rejection, an
 * `ApiError`, a browser `DOMException` from a WebAuthn prompt, a string a
 * library threw. Screens read the text through `errorMessage`, never
 * `err.message`, so the mapping from protocol codes to sentences a person can
 * act on lives here and nowhere else.
 */

/** A rejection's framework code, bare (`permissionDenied`) or namespaced
 *  (`did-management:notFound`), without importing the transport. */
function rejectionCode(e: unknown): string | null {
  const payload = (e as { payload?: { code?: unknown } } | null)?.payload;
  if (!payload || typeof payload.code !== "string") return null;
  const c = payload.code;
  const i = c.lastIndexOf(":");
  return i >= 0 ? c.slice(i + 1) : c;
}

function rejectionDetail(e: unknown): string | null {
  const m = (e as { payload?: { message?: unknown } } | null)?.payload?.message;
  return typeof m === "string" && m ? m : null;
}

function httpStatus(e: unknown): number | null {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === "number" ? s : null;
}

/** How to get a stepped-up session, when the console cannot do it in place. */
export const STEP_UP_GUIDANCE =
  "This action needs a stepped-up sign-in, and this session cannot be stepped up here: the connected wallet does not support step-up. Sign out, sign in again with a passkey (a passkey sign-in counts as stepped up for the whole session) or with a wallet that supports step-up, then retry.";

/** A browser WebAuthn prompt that was dismissed, timed out or refused. */
export const PASSKEY_CANCELLED = "Passkey prompt was cancelled or timed out.";

const CODE_MESSAGES: Record<string, string> = {
  permissionDenied: "You don't have permission to do this.",
  forbidden: "You don't have permission to do this.",
  unauthorized: "Your session has ended. Sign in again.",
  notFound: "Not found — it may have been deleted, or the address is wrong.",
  unknownDomain: "That domain is not hosted here.",
  unavailable: "The control plane is temporarily unavailable. Try again in a moment.",
  internalError:
    "The control plane hit an internal error. Try again; if it persists, check its log.",
  conflict: "Someone else changed this at the same time. Reload and try again.",
  quotaExceeded: "This would exceed the account's quota.",
  stepUpRequired: STEP_UP_GUIDANCE,
};

/** Wrap a human sentence around the server's detail, when it adds anything. */
function withDetail(human: string, detail: string | null, code: string): string {
  if (!detail || detail === code || human.includes(detail)) return human;
  return `${human} (${detail})`;
}

/**
 * The message to show for a caught value.
 *
 * Known rejection codes become sentences; the server's own words are kept in
 * brackets after them, because they often name the exact rule. Anything else
 * falls back to its message, then to `fallback`.
 */
export function errorMessage(e: unknown, fallback = "Something went wrong."): string {
  const code = rejectionCode(e);
  const detail = rejectionDetail(e);
  if (code) {
    if (detail === "step_up_required") return STEP_UP_GUIDANCE;
    const human = CODE_MESSAGES[code];
    if (human) return withDetail(human, detail, code);
    return detail ?? fallback;
  }

  // A WebAuthn prompt the operator closed, or that timed out.
  const name = (e as { name?: unknown } | null)?.name;
  if (name === "NotAllowedError" || name === "AbortError") return PASSKEY_CANCELLED;

  const message =
    e instanceof Error && e.message ? e.message : typeof e === "string" && e ? e : null;

  // `fetch` itself failed: offline, DNS, the control plane down.
  if (e instanceof TypeError && /fetch|network/i.test(message ?? "")) {
    return "Could not reach the control plane. Check your connection and try again.";
  }
  // `checkReply` refused a reply that did not verify.
  if (message?.startsWith("refused the reply to ")) {
    return "The control plane's reply could not be verified, so it was not used. Try again; if it persists, the service identity may have changed.";
  }

  const status = httpStatus(e);
  if (status === 401) return CODE_MESSAGES.unauthorized!;
  if (status !== null && status >= 500 && status !== 501 && !message) {
    return CODE_MESSAGES.unavailable!;
  }
  return message ?? fallback;
}

/** Whether `e` says the thing asked for does not exist. */
export function isNotFound(e: unknown): boolean {
  return rejectionCode(e) === "notFound" || httpStatus(e) === 404;
}
