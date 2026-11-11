/**
 * Resolve a set of DIDs to the agent names they serve.
 *
 * The reverse of the `/@name` redirect, for the surfaces that hold a DID and
 * want to show its handle: the dashboard, the servers list, the settings page,
 * a DID's owner row. Those pages each fetch their DIDs separately, so the hook
 * takes whatever they already have and asks for the names in one request.
 *
 * ## Failure is silence
 *
 * Every failure — the request erroring, an older deployment with no such route,
 * the feature being off — yields an empty map, so callers render the DID alone
 * exactly as they did before names existed. A handle is a convenience; none of
 * these screens should break, or even show an error, because one could not be
 * resolved.
 *
 * ## Only locally-hosted DIDs resolve
 *
 * The control plane answers for DIDs it hosts, not for foreign ones — it can
 * only vouch for names it actually serves. A DID hosted elsewhere comes back
 * absent, which renders as no chip. That is correct rather than a gap: showing
 * an unverified name for somebody else's DID is precisely what Layer-1
 * verification exists to prevent.
 */
import { useEffect, useMemo, useState } from "react";
import { api } from "./api";

/**
 * @param dids DIDs to resolve. Nullish entries and duplicates are fine — they
 *   are dropped before the request, so callers can pass optional fields
 *   straight through without pre-filtering.
 * @param opts.background The lookup follows a timer-driven refresh (a polling
 *   page), so it is sent as a background request and does not count as
 *   session activity. See `lib/poll.ts`.
 * @returns DID -> served names (bare local parts). Absent keys mean no names;
 *   read with `names[did] ?? []`.
 */
export function useAgentNames(
  dids: (string | null | undefined)[],
  opts: { background?: boolean } = {},
): Record<string, string[]> {
  const background = opts.background ?? false;
  const [names, setNames] = useState<Record<string, string[]>>({});

  // Sort so a caller re-ordering its list doesn't refetch, and join into a
  // primitive: a fresh array literal every render would make the effect's
  // dependency change on every render and loop.
  //
  // A space is a safe separator because a DID is a URI and cannot contain
  // whitespace, so the `split` below always reproduces the input exactly.
  const key = useMemo(
    () =>
      Array.from(new Set(dids.filter((d): d is string => !!d)))
        .sort()
        .join(" "),
    [dids],
  );

  useEffect(() => {
    if (!key) {
      setNames({});
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const res = await api.resolveAgentNames(key.split(" "), { background });
        if (!cancelled) setNames(res.names ?? {});
      } catch {
        // Best-effort — see the module doc. Render the DIDs alone.
        if (!cancelled) setNames({});
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [key, background]);

  return names;
}
