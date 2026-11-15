/** Agent-name helpers for the DID detail screen. */

import type { DidDetailResponse } from "../../lib/api";
import { extractDidHost } from "../../lib/domain";

/** The hosting domain a name is scoped to — the DID's own host. Prefer the
 *  record's tagged `domain`; fall back to the host segment of the identifier.
 *
 *  Delegates to the shared [`extractDidHost`] rather than re-parsing here. A
 *  local copy once required at least five colon-separated segments, which
 *  silently excluded **root DIDs**: `did:webvh:<scid>:<host>` has exactly four,
 *  because the root DID's path is implicit (`/.well-known/did.jsonl`). A root
 *  record whose `domain` had not been tagged therefore resolved to no domain
 *  at all, disabling the whole Agent Names card — on precisely the DID that
 *  owns the domain's community name. */
export function agentDomainOf(detail: DidDetailResponse | null | undefined): string | null {
  return detail?.domain || extractDidHost(detail?.didId);
}

/** How a bound name is written back to the operator.
 *
 *  `@alice` for an ordinary name, and `domain/@` for the community name —
 *  whose local part is empty, so the usual `@` + local part renders as a lone
 *  `@` and reads as a typo or a stray character in a confirm dialog. */
export function agentNameLabel(name: string, domain: string | null): string {
  return name === "" ? `${domain ?? ""}/@` : `@${name}`;
}

/** If `aka` is an agent name (`…/@local`) on `domain`, return its local part.
 *  Host match is case-insensitive; the local part is returned verbatim (the
 *  spec compares it case-sensitively).
 *
 *  Returns `""` — not `null` — for the **community name** (`domain/@`), whose
 *  local part is genuinely empty. `null` means "not an agent name on this
 *  domain" and is the only value callers should discard; a caller that filters
 *  on truthiness instead drops the community name along with the non-matches. */
export function agentNameLocalPart(aka: string, domain: string): string | null {
  const noScheme = aka.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const marker = noScheme.indexOf("/@");
  if (marker < 0) return null;
  const host = noScheme.slice(0, marker);
  const local = noScheme.slice(marker + 2).split("/")[0] ?? "";
  if (host.toLowerCase() !== domain.toLowerCase()) return null;
  return local;
}

/** The string members of an unchecked `alsoKnownAs`. */
export function alsoKnownAsOf(aka: unknown): string[] {
  return Array.isArray(aka) ? aka.filter((a): a is string => typeof a === "string") : [];
}
