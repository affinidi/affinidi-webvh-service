/**
 * The `?next=` return address of the sign-in page.
 *
 * It arrives in the URL, so anyone can craft it: only a path on this origin is
 * honoured. A single leading `/` and nothing that a browser would read as
 * another host — `//evil.example` and `/\evil.example` are protocol-relative
 * URLs, and a scheme (`javascript:`) has no leading slash at all.
 */

/** Routes that must not be returned to after signing in. */
const NO_RETURN = ["/login", "/enroll"];

/** `raw` as a same-origin path to go to after sign-in, or `null`. */
export function safeNextPath(raw: unknown): string | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) return null;
  if (!value.startsWith("/")) return null;
  if (value.startsWith("//") || value.startsWith("/\\")) return null;
  // Control characters (a tab or newline inside "//" is still "//" to a URL
  // parser) and backslashes anywhere are never part of a console path.
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return null;
  const path = value.split(/[?#]/)[0]!;
  if (NO_RETURN.some((r) => path === r || path.startsWith(`${r}/`))) return null;
  return value;
}

/** The sign-in page's address, returning to `current` afterwards. */
export function loginHref(current: string | null | undefined): string {
  const next = safeNextPath(current);
  return next && next !== "/" ? `/login?next=${encodeURIComponent(next)}` : "/login";
}

/** Where this tab is, as a path with its query — what `?next=` should hold. */
export function currentPath(fallback: string): string {
  if (typeof window !== "undefined" && window.location) {
    return `${window.location.pathname}${window.location.search}`;
  }
  return fallback;
}
