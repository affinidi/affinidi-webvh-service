/**
 * What to tell an operator before and after they ask their agent to sign for a
 * DID this service hosts.
 *
 * Two different failures, and the difference matters because the obvious guard
 * only catches one of them:
 *
 *  - **Someone else's DID.** A control-plane admin sees every DID on the server
 *    (`list_dids` returns all of them when the caller is admin and names no
 *    owner), and the delegated-edit button was offered on all of them. Asking
 *    your agent to sign for a DID it never minted cannot work: it holds no
 *    update key for it.
 *
 *  - **An orphan.** The host still serves a DID your agent has *deleted*.
 *    `delete_did_webvh` calls the host first and, if that call fails, logs
 *    "continuing local cleanup but DID is now orphaned on the daemon" and
 *    removes the local record anyway. The host record keeps its `owner` — your
 *    agent — so an owner check says yes, and the edit fails at signing.
 *
 * Which is why this module does not pretend to be a gate. The page cannot know
 * which agent the wallet is connected to (`walletDefaults()` returns only the
 * step-up VTA), and an orphan passes any ownership test there is. What it can
 * do is warn where a mismatch is visible, and turn the *specific* rejection the
 * agent sends back into the command that resolves it.
 *
 * Import-free on purpose so the test runner can reach it: `wallet.ts` pulls in
 * `react-native`, which vitest cannot parse.
 */

/**
 * Warn when the DID's owner is not the identity this session authenticated as.
 *
 * `null` when there is nothing useful to say — either they match, or one of
 * them is unknown, in which case silence beats a warning the operator cannot
 * act on.
 *
 * Deliberately a warning and not a disabled button. The signer is the wallet's
 * VTA, which this page cannot identify, so "owner ≠ session DID" means *likely
 * to fail*, not *certain to*: an operator logged in with a passkey while their
 * wallet holds the owning agent is a legitimate case that a hard gate would
 * block outright.
 */
export function ownerMismatchWarning(
  owner: string | null | undefined,
  sessionDid: string | null | undefined,
): string | null {
  if (!owner || !sessionDid) return null;
  if (owner === sessionDid) return null;
  return (
    `This DID is owned by ${owner}, not the identity you signed in as. ` +
    `Your agent can only sign for DIDs it holds the update key for, so this ` +
    `will fail unless your wallet is connected to that agent.`
  );
}

/**
 * The Trust-Task error codes an agent uses for "I have no record of this DID".
 *
 * `taskFailed` is what the VTA maps `AppError::NotFound` onto
 * (`app_error_to_reject`), so the code alone is not specific enough — the
 * message is what distinguishes a missing DID from any other task failure.
 */
const NOT_FOUND_CODES = new Set(["taskFailed", "task_failed", "notFound", "not_found"]);

/**
 * Recognise "your agent does not hold this DID" in a rejection, and say what to
 * do about it.
 *
 * The VTA answers `did not found: SCID <did> not found` — accurate, and
 * useless to an operator looking at a DID the host is serving right now. It
 * reads as data loss. It usually is not: the agent deleted the DID and the
 * host kept it, so the fix is to reconcile the two rather than to go hunting
 * for keys.
 *
 * Returns `null` for anything else, so an unrelated failure keeps its own
 * message rather than being papered over with advice that does not apply.
 */
export function orphanHint(code: string | undefined, message: string | undefined): string | null {
  if (!message) return null;
  const notFound =
    /\bnot found\b/i.test(message) && (code === undefined || NOT_FOUND_CODES.has(code));
  if (!notFound) return null;
  return (
    "Your agent has no record of this DID, so it holds no update key for it. " +
    "That usually means the DID was deleted at the agent while this host kept " +
    "serving it. Run `pnm did-mgmt dids reconcile --server <id>` to list DIDs " +
    "the host has and the agent does not."
  );
}
