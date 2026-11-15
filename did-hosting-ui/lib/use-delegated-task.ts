/**
 * The consent / re-submit state machine behind every delegated edit on the DID
 * detail screen — a document publish, an agent-name park or resume, a did:scid
 * alias change.
 *
 * We do not hold the DID's update key and never will. The page proposes an
 * edit through the wallet's `requestTask`; the user's VTA decides, and may
 * refuse with `consentRequired` until a human approves on another device.
 *
 * The approval is bound to a digest of the *payload*, so a retry MUST send the
 * identical request. On a `consentRequired` refusal the exact re-submit is
 * pinned (a ref: read only from the grant-event handler and the manual button,
 * never rendered), together with the log version it was composed against.
 *
 * Two ways out of a pending approval:
 *
 * - **Event-driven re-submit.** The wallet emits `vtawallet:consentgranted`
 *   (with the payload digest) the instant the VTA reports the grant; the
 *   pinned re-submit is replayed once, silently. There is deliberately no
 *   timer that *re-submits*: every re-submit goes through the wallet's
 *   un-skippable worker-mode confirm, and a loop would re-open it every tick.
 * - **Read-only watch.** While an approval is outstanding the log is re-read
 *   on a timer (a background read that touches no wallet). The grant event
 *   only reaches the tab that relayed the decision — approve on a paired
 *   mobile approver and nothing is dispatched here — so without this the page
 *   would sit on a stale document whose pinned payload can only fail as a
 *   `concurrent update`. Once the log moves past the pinned version, the
 *   pinned payload is retired and `onMovedOn` is told.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import type { LogEntryInfo } from "./api";
import { orphanHint } from "./delegation-guard";
import { errorMessage } from "./errors";
import { hasLogMovedPast } from "./pinned-edit";
import { startPolling } from "./poll";
import type { RequestTaskOutcome, TaskConsentRequired } from "./wallet";

/** What one attempt came to: keep waiting (`consent`), done (`accepted`), or
 *  failed (`error`). */
export type DelegatedResult = "accepted" | "consent" | "error";

/** Replays the exact request an approval is bound to. `silent` is the
 *  grant-event replay: no spinner, no error toast — but a granted update is
 *  always announced. */
export type Resubmit = (opts?: { silent?: boolean }) => Promise<DelegatedResult>;

/** Which card raised the outstanding approval, so its code is shown once,
 *  beside the action that asked for it. */
export type ConsentOrigin = "scidAlias" | "other";

/** The event the wallet dispatches when an approval lands. */
export const CONSENT_GRANTED_EVENT = "vtawallet:consentgranted";

export interface UseDelegatedTaskOptions {
  /** The latest log `versionId` as the page shows it — pinned with a consent. */
  latestVersionId: string | null;
  /** After an accepted task (the success message has been shown). */
  onAccepted: () => void;
  /** Re-read the log as a background request while an approval is pending.
   *  Omitted: no watch. */
  readLog?: () => Promise<LogEntryInfo[]>;
  /** The log moved past the pinned version; the pending approval is retired. */
  onMovedOn?: (entries: LogEntryInfo[]) => void;
  /** How a result is told to the operator. */
  notify: (title: string, message: string) => void;
  /** The watch interval, ms. Default 5000. */
  pollIntervalMs?: number;
}

export interface DelegatedTask {
  /** An attempt the operator started is running. */
  publishing: boolean;
  /** The outstanding approval, if any. */
  consent: TaskConsentRequired | null;
  consentOrigin: ConsentOrigin;
  /** Run one delegated task. `submit` and `resubmit` MUST produce the same
   *  payload, or the approved digest will not match. */
  run: (
    submit: () => Promise<RequestTaskOutcome>,
    resubmit: Resubmit,
    successMsg: string,
    opts?: { silent?: boolean },
    origin?: ConsentOrigin,
  ) => Promise<DelegatedResult>;
  /** The manual "I have approved it" button: replay the pinned request. */
  resubmitNow: () => void;
}

export function useDelegatedTask(options: UseDelegatedTaskOptions): DelegatedTask {
  const [publishing, setPublishing] = useState(false);
  const [consent, setConsent] = useState<TaskConsentRequired | null>(null);
  const [consentOrigin, setConsentOrigin] = useState<ConsentOrigin>("other");
  const resubmitRef = useRef<Resubmit | null>(null);
  const pinnedVersionRef = useRef<string | null>(null);

  // The latest callbacks, read from the stable `run` and the effects below
  // without making them re-run on every render.
  const optsRef = useRef(options);
  optsRef.current = options;

  const retire = useCallback(() => {
    resubmitRef.current = null;
    pinnedVersionRef.current = null;
    setConsent(null);
  }, []);

  const run = useCallback<DelegatedTask["run"]>(
    async (submit, resubmit, successMsg, opts, origin = "other") => {
      const silent = opts?.silent ?? false;
      if (!silent) setPublishing(true);
      try {
        const outcome = await submit();
        if (outcome.kind === "consentRequired") {
          resubmitRef.current = resubmit;
          pinnedVersionRef.current = optsRef.current.latestVersionId;
          setConsentOrigin(origin);
          setConsent(outcome);
          return "consent";
        }
        retire();
        optsRef.current.notify("Done", successMsg);
        optsRef.current.onAccepted();
        return "accepted";
      } catch (e: unknown) {
        // The wallet flattens the agent's rejection to a message string on its
        // way through the extension bridge, so there is no `code` here — the
        // message is all we get, and `orphanHint` is written to work from it.
        const message = errorMessage(e, "The request failed.");
        const hint = orphanHint(undefined, message);
        if (!silent) optsRef.current.notify("Error", hint ? `${message}\n\n${hint}` : message);
        return "error";
      } finally {
        if (!silent) setPublishing(false);
      }
    },
    [retire],
  );

  const resubmitNow = useCallback(() => {
    void resubmitRef.current?.();
  }, []);

  // Event-driven: re-attempt the instant the wallet reports our approval.
  const digest = consent?.payloadDigest;
  useEffect(() => {
    if (!digest || typeof window === "undefined" || !window.addEventListener) return;
    const onGranted = (ev: Event) => {
      const detail = (ev as CustomEvent<{ payloadDigest?: string } | undefined>).detail;
      // Only the approval we're waiting on — ignore events for other tasks.
      if (detail?.payloadDigest !== digest) return;
      void resubmitRef.current?.({ silent: true });
    };
    window.addEventListener(CONSENT_GRANTED_EVENT, onGranted);
    return () => window.removeEventListener(CONSENT_GRANTED_EVENT, onGranted);
  }, [digest]);

  // Read-only watch while an approval is outstanding.
  const watching = consent !== null && options.readLog !== undefined;
  const interval = options.pollIntervalMs ?? 5000;
  useEffect(() => {
    if (!watching) return;
    let cancelled = false;
    const check = async () => {
      const readLog = optsRef.current.readLog;
      if (!readLog) return;
      let entries: LogEntryInfo[];
      try {
        entries = await readLog();
      } catch {
        // Transient — the next tick retries. Never surfaced: a failed poll is
        // indistinguishable to the user from still waiting.
        return;
      }
      if (cancelled) return;
      // Unchanged — still genuinely waiting on the approver.
      if (!hasLogMovedPast(pinnedVersionRef.current, entries)) return;
      // The log moved. Whatever the pinned payload was, it can no longer
      // apply, so retire it rather than leave a button that can only fail.
      retire();
      optsRef.current.onMovedOn?.(entries);
    };
    void check();
    const stop = startPolling(() => void check(), interval);
    return () => {
      cancelled = true;
      stop();
    };
  }, [watching, interval, retire]);

  return { publishing, consent, consentOrigin, run, resubmitNow };
}
