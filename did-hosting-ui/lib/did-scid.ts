// did:scid:vh:1 — a DID verified by the same did:webvh log, but not bound to
// the host serving it. The identity is `did:scid:vh:1:<scid>`; `?src=<host>/<path>`
// is a locator for the log, not part of it (VTI-KEY-160 of the VTI
// specification). A hosted did:webvh log may list its did:scid alias in
// `alsoKnownAs`, which links the two forms as one subject (VTI-KEY-164).

const PREFIX = "did:scid:vh:1:";

export interface ScidParts {
  /** The self-certifying identifier. */
  scid: string;
  /** The `src` locator (`host[/path]`), when the DID URL carries one. */
  src: string | null;
}

/** Split a `did:scid:vh:1` DID or DID URL, or `null` for anything else. */
export function parseScid(did: string | undefined | null): ScidParts | null {
  if (!did || !did.startsWith(PREFIX)) return null;
  const rest = did.slice(PREFIX.length).split("#")[0];
  const q = rest.indexOf("?");
  const scid = q === -1 ? rest : rest.slice(0, q);
  if (!scid || scid.includes(":") || scid.includes("/")) return null;
  let src: string | null = null;
  if (q !== -1) {
    const query = rest.slice(q + 1);
    if (!query.startsWith("src=") || query.includes("&")) return null;
    src = query.slice("src=".length) || null;
  }
  return { scid, src };
}

/** The host a did:scid's `src` names (scheme and path stripped, decoded), or
 *  `null` for a bare did:scid, which names none. */
export function scidHost(did: string): string | null {
  const parts = parseScid(did);
  if (!parts?.src) return null;
  const src = parts.src.replace(/^https?:\/\//, "");
  const host = src.split("/")[0];
  if (!host) return null;
  try {
    return decodeURIComponent(host);
  } catch {
    return null;
  }
}

/** The did:scid aliases a hosted did:webvh document lists for itself: the
 *  `alsoKnownAs` entries in the did:scid:vh:1 form with the log's own SCID. */
export function scidAliasesOf(webvhDid: string | undefined | null, alsoKnownAs: unknown): string[] {
  if (!webvhDid?.startsWith("did:webvh:") || !Array.isArray(alsoKnownAs)) return [];
  const scid = webvhDid.split(":")[2];
  return alsoKnownAs.filter(
    (a): a is string => typeof a === "string" && parseScid(a)?.scid === scid,
  );
}
