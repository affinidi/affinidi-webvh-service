/**
 * Whether an edit pinned to one log version has been overtaken.
 *
 * A delegated publish that needs human approval is pinned twice over: the
 * approval is bound to a digest of the exact payload, and the payload itself
 * carries the `expectedVersionId` it was composed against. Both are deliberate
 * — see the DID detail screen — but together they mean a pinned edit is
 * single-use. Once the log moves, the VTA's dry-run rejects the payload as a
 * `concurrent update` and no amount of re-submitting will change that.
 *
 * The screen therefore has to be able to tell "still waiting on the approver"
 * from "already overtaken", and it cannot rely on being told: the wallet's
 * grant event only reaches the tab that relayed the decision, so an approval
 * granted on a paired mobile approver applies server-side with nothing to
 * dispatch back. Re-reading the log is the only signal available, and this is
 * the rule it is read by.
 */

/** The subset of a log entry this rule needs. */
export interface PinnedEditVersion {
  versionId?: string | null;
}

/**
 * Has the log moved past the version a pinned edit was composed against?
 *
 * @param pinned The `versionId` captured when the approval was requested.
 *   `null` when the DID had no published log at that point.
 * @param entries The log as most recently read.
 *
 * `false` whenever the answer is not knowable — an empty log, or an entry with
 * no `versionId`. Both are read as "nothing observed yet" rather than as
 * movement, because the caller's response to `true` is to retire the pending
 * approval, and doing that on a failed or partial read would discard a
 * perfectly good approval the user is still waiting on.
 */
export function hasLogMovedPast(
  pinned: string | null,
  entries: readonly PinnedEditVersion[],
): boolean {
  const latest = entries[entries.length - 1]?.versionId ?? null;
  if (!latest) return false;
  return latest !== pinned;
}
