/**
 * The did:scid alias of a hosted did:webvh DID — what the DID page shows about
 * it and what it can offer to change.
 *
 * Every did:webvh log is also `did:scid:vh:1:<scid>`; the two forms are one
 * subject only while the did:webvh document lists the did:scid DID URL in
 * `alsoKnownAs` (VTI-KEY-164). The control plane reports the latest document's
 * state in `did/info` (`ext["vnd.affinidi.webvh"].scidAlias`): the DID URL it
 * would list for the log's current location, and whether it is listed, not
 * listed, or listed for an old location. This page never derives the `src`
 * locator itself — one derivation, on the server.
 *
 * Who can change it:
 *
 *  - **This hosting service holds no update key for any DID it hosts for an
 *    owner.** The owner's agent (a VTA) signs; this page can only *ask* it,
 *    through the wallet's task relay, with `vta/webvh/dids/update/1.1`'s
 *    `scidAlsoKnownAs` — the agent edits `alsoKnownAs`, signs and publishes,
 *    exactly as for parking an agent name. Without the relay the state is
 *    read-only here and changed from the controller's own console.
 *  - **The service's own DIDs (owner `system`)** are signed by the service,
 *    offline: `identity-scid-alias list|remove` with the service stopped.
 *
 * Import-free on purpose so the test runner can reach it: `wallet.ts` pulls in
 * `react-native`, which vitest cannot parse.
 */

export type ScidAliasStatus = "listed" | "notListed" | "stale";

export interface ScidAliasState {
  /** The DID URL the document lists, or would: `did:scid:vh:1:<scid>?src=…`. */
  didUrl: string;
  status: ScidAliasStatus;
}

/** Read `scidAlias` off the host extension of a `did/info` record, or `null`
 *  (not a did:webvh log, nothing published, or an older control plane). */
export function scidAliasFromExt(webvhExt: Record<string, unknown>): ScidAliasState | null {
  const v = webvhExt.scidAlias as Record<string, unknown> | undefined;
  if (!v || typeof v !== "object") return null;
  const { didUrl, status } = v;
  if (typeof didUrl !== "string" || !didUrl.startsWith("did:scid:vh:1:")) return null;
  if (status !== "listed" && status !== "notListed" && status !== "stale") return null;
  return { didUrl, status };
}

/** `true` lists the alias for the current location (replacing a stale one);
 *  `false` removes every did:scid entry of this SCID. */
export type ScidAliasAction = { label: string; scidAlsoKnownAs: boolean };

export interface ScidAliasView {
  /** One line: what the latest document says. */
  summary: string;
  /** What can be done here; empty when the state is read-only on this page. */
  actions: ScidAliasAction[];
  /** Why there are no actions, and where the change is made instead. */
  readOnlyReason: string | null;
  /** Shown before any action: what publishing the entry does to the key. */
  warning: string | null;
}

/** The service's own DIDs are recorded with this owner (`bootstrap_did`). */
export const SYSTEM_OWNER = "system";

/** What the DID page shows for the alias, given who can sign for this DID. */
export function scidAliasView(args: {
  alias: ScidAliasState;
  owner: string | null | undefined;
  /** The wallet's task relay is present, so this page can ask the agent. */
  canDelegate: boolean;
  /** The log's latest parameters commit to pre-rotation (`nextKeyHashes`). */
  preRotation: boolean;
}): ScidAliasView {
  const { alias, owner, canDelegate, preRotation } = args;
  const summary =
    alias.status === "listed"
      ? "Listed — this DID and its did:scid form are one subject."
      : alias.status === "stale"
        ? "Listed for an old location — the did:scid entry in alsoKnownAs names a different src than where this log is now served."
        : "Not listed — this DID and its did:scid form are separate identities.";

  if (owner === SYSTEM_OWNER) {
    return {
      summary,
      actions: [],
      readOnlyReason:
        "This is a service DID, signed by the service itself. If it is this service's own identity, an operator changes it with `identity-scid-alias list` or `identity-scid-alias remove` while the service is stopped; the update key does not rotate.",
      warning: null,
    };
  }

  if (!canDelegate) {
    return {
      summary,
      actions: [],
      readOnlyReason:
        "This host does not hold this DID's update key, so the alias is changed by the DID's controller. For a DID held by a VTA, use pnm or the browser-plugin console (vta/webvh/dids/update/1.1, scidAlsoKnownAs) — or connect your agent wallet to ask it from here.",
      warning: null,
    };
  }

  const actions: ScidAliasAction[] =
    alias.status === "listed"
      ? [{ label: "Remove alias", scidAlsoKnownAs: false }]
      : alias.status === "stale"
        ? [
            { label: "List for current location", scidAlsoKnownAs: true },
            { label: "Remove alias", scidAlsoKnownAs: false },
          ]
        : [{ label: "List alias", scidAlsoKnownAs: true }];

  return {
    summary,
    actions,
    readOnlyReason: null,
    warning:
      "Your agent publishes a new, permanent log entry for this and rotates the DID's update key" +
      (preRotation ? " to the next pre-committed key (this log uses pre-rotation)" : "") +
      " — the current update key stops being able to authorise changes.",
  };
}

/** The confirm text for one action. */
export function scidAliasConfirm(alias: ScidAliasState, action: ScidAliasAction): string {
  return action.scidAlsoKnownAs
    ? `List ${alias.didUrl} in this DID's alsoKnownAs? From the version that lists it, the did:webvh and did:scid forms are one subject.`
    : "Remove every did:scid entry for this DID's SCID from alsoKnownAs? From that version on, the did:webvh and did:scid forms are separate identities — anything relying on the did:scid form stops treating them as one.";
}
