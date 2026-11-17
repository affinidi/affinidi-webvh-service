/**
 * What a delegated edit of a **did:webs** DID can ask the agent for.
 *
 * Every delegated edit on the detail page used to go out as
 * `vta/webvh/dids/update/1.0`. A VTA keeps its did:webs DIDs in a separate store
 * from its did:webvh ones, and the webvh handler looks only at its own store, so
 * for a did:webs DID it answered `SCID did:webs:… not found`. That reads like
 * the agent lost the DID. It hasn't; the request went to the wrong handler.
 *
 * did:webs has its own task, `vta/webs/dids/update/0.1`, and it does not take a
 * document. A did:webs document is rendered from the AID's key event log, so the
 * only parts an update can change are the designations anchored in that log:
 * further aliases (DIDs only), services, and the key agreement key. This page
 * offers only the alias change, because that is the one a document edit maps
 * onto exactly. Anything else is refused here, before the agent is asked, with
 * the reason given.
 *
 * Import-free on purpose so the test runner can reach it (see
 * `delegation-guard.ts`).
 */

export const WEBS_DIDS_UPDATE_0_1 = "https://trusttasks.org/spec/vta/webs/dids/update/0.1";

export function isDidWebs(did: string | null | undefined): boolean {
  return typeof did === "string" && did.startsWith("did:webs:");
}

/** Matches the task schema's `alsoKnownAs` item pattern. */
const DID_ALIAS = /^did:[a-z0-9]+:.+$/;

/**
 * The aliases the agent puts in every did:webs document itself: the DID, its
 * did:web form and its did:keri form. The task neither takes nor lists them
 * (VTA `further_aliases`), so they are removed before comparing or sending.
 */
function impliedAliases(did: string): Set<string> {
  const aid = did.slice(did.lastIndexOf(":") + 1);
  return new Set([did, did.replace(/^did:webs:/, "did:web:"), `did:keri:${aid}`]);
}

function aliasesOf(aka: unknown): string[] {
  return Array.isArray(aka) ? aka.filter((a): a is string => typeof a === "string") : [];
}

/** The further aliases a document lists: what `alsoKnownAs` in the task means. */
export function furtherAliases(did: string, aka: unknown): string[] {
  const implied = impliedAliases(did);
  return aliasesOf(aka).filter((a) => !implied.has(a));
}

function sameMembers(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const x = [...a].sort();
  const y = [...b].sort();
  return x.every((v, i) => v === y[i]);
}

function stableJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stableJson).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableJson(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

export type WebsEditPlan =
  { kind: "aliases"; alsoKnownAs: string[] } | { kind: "refused"; reason: string };

/**
 * Turn "publish `next` in place of `current`" into a did:webs update, or say
 * why there isn't one.
 */
export function planWebsEdit(
  did: string,
  current: Record<string, unknown> | null | undefined,
  next: Record<string, unknown>,
): WebsEditPlan {
  const { alsoKnownAs: curAka, ...curRest } = current ?? {};
  const { alsoKnownAs: nextAka, ...nextRest } = next;

  if (stableJson(curRest) !== stableJson(nextRest)) {
    return {
      kind: "refused",
      reason:
        "This is a did:webs DID. Its document is built from its key event log, so it " +
        "cannot be edited directly. Through this page your agent can change only its " +
        "alsoKnownAs DID aliases. To change services or rotate keys, use pnm " +
        "(vta/webs/dids/update or rotate-keys).",
    };
  }

  const wanted = furtherAliases(did, nextAka);
  const notDids = wanted.filter((a) => !DID_ALIAS.test(a));
  if (notDids.length > 0) {
    return {
      kind: "refused",
      reason:
        `A did:webs DID can list only other DIDs in alsoKnownAs, not ${notDids.join(", ")}. ` +
        "Agent names (https://…/@name) are not supported for did:webs yet.",
    };
  }

  if (sameMembers(wanted, furtherAliases(did, curAka))) {
    return { kind: "refused", reason: "Nothing to change: the aliases are already these." };
  }
  return { kind: "aliases", alsoKnownAs: wanted };
}

/** Why park/resume cannot be offered for a did:webs DID. */
export const WEBS_AGENT_NAMES_UNSUPPORTED =
  "Agent names are not supported for did:webs DIDs yet. Your agent can list only " +
  "other DIDs in a did:webs document's alsoKnownAs.";
