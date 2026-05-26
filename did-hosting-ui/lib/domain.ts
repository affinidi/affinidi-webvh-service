// Domain-matching helpers shared between the DIDs list view and the
// dashboard's per-domain stats. The post-M-01 invariant is that
// `DidRecord.domain` carries the canonical host for every record, but
// upgrades have a window where freshly-created entries (and any legacy
// rows that the M-01 sweep hasn't backfilled yet) still carry an empty
// `domain` field. In that window we fall back to splitting the
// `did_id` itself — that string IS the canonical host, just buried
// in a slot the UI's old code never read.
//
// Keeping this in one place — both `app/index.tsx` and
// `app/dids/index.tsx` consume it — avoids a third forked copy of the
// did:webvh / did:web index dance the next time someone touches a
// per-domain view.

import type { DidRecord } from "./api";

/** Extract the canonical host (resolution authority) from a DID. */
//
// `did:webvh:<scid>:<host>:<...path...>`  → index 3
// `did:web:<host>:<...path...>`           → index 2
//
// Hosts with non-default ports are percent-encoded (e.g.
// `localhost%3A8534`); the caller compares against
// `currentDomain` which is unencoded, so we `decodeURIComponent`
// before returning. Returns `null` for unsupported DID methods or
// malformed input — callers treat that as "no host known".
export function extractDidHost(didId: string | undefined | null): string | null {
  if (!didId) return null;
  const parts = didId.split(":");
  let host: string | undefined;
  if (parts[1] === "webvh") {
    host = parts[3];
  } else if (parts[1] === "web") {
    host = parts[2];
  }
  if (!host) return null;
  try {
    return decodeURIComponent(host);
  } catch {
    // Malformed percent-encoding — treat as no usable host.
    return null;
  }
}

/** True iff this record belongs to `targetDomain`.
 *
 * Prefers the persisted `record.domain` field (post-M-01 invariant).
 * Falls back to the `did_id`'s host segment so the UI doesn't read as
 * empty in the upgrade window between the backend fix landing and the
 * M-01 backfill sweep next running. */
export function matchesDomain(record: DidRecord, targetDomain: string): boolean {
  if (record.domain) return record.domain === targetDomain;
  const host = extractDidHost(record.didId);
  return host === targetDomain;
}
