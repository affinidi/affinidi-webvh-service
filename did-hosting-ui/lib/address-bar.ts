/**
 * Reading a one-time secret (an enrolment invite token) out of the page's
 * address and then taking it out of the address bar.
 *
 * Invite links carry the token in the fragment (`/enroll#token=…`), which a
 * browser never sends: it stays out of the web host's request line, its
 * access log and any `Referer`. Links issued before that carried it in the
 * query (`/enroll?token=…`), so the query is still read as a fallback.
 */

/** `name` from the fragment (`#name=…`) of `href`, else from its query. */
export function readAddressParam(href: string, name: string): string | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  const fragment = new URLSearchParams(url.hash.replace(/^#/, ""));
  const fromFragment = fragment.get(name);
  if (fromFragment) return fromFragment;
  const fromQuery = url.searchParams.get(name);
  return fromQuery || null;
}

/** `href` with `name` removed from both its fragment and its query, as a
 *  path (`/enroll?other=1#other=2`), or `null` when it holds neither. */
export function withoutAddressParam(href: string, name: string): string | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  const fragment = new URLSearchParams(url.hash.replace(/^#/, ""));
  const inFragment = fragment.has(name);
  const inQuery = url.searchParams.has(name);
  if (!inFragment && !inQuery) return null;
  url.searchParams.delete(name);
  let hash = url.hash;
  if (inFragment) {
    fragment.delete(name);
    const rest = fragment.toString();
    hash = rest ? `#${rest}` : "";
  }
  return `${url.pathname}${url.search}${hash}`;
}

/**
 * The value of `name` in the current page's address (fragment first, then
 * query), or `null`. Off the web (native builds) always `null`.
 */
export function readPageParam(name: string): string | null {
  if (typeof window === "undefined" || !window.location?.href) return null;
  return readAddressParam(window.location.href, name);
}

/**
 * Remove `name` from the page's fragment and query in place, with
 * `history.replaceState`: the address bar and the current history entry stop
 * showing it, and nothing is reloaded or navigated. No-op off the web or
 * when the parameter is absent.
 */
export function stripPageParam(name: string): void {
  if (typeof window === "undefined") return;
  const { history, location } = window;
  if (!history?.replaceState || !location?.href) return;
  const next = withoutAddressParam(location.href, name);
  if (next === null) return;
  history.replaceState(history.state, "", next);
}

/**
 * Ask the browser to send no `Referer` from this page, for a host that does
 * not already set `Referrer-Policy: no-referrer` on it (the control plane and
 * the daemon do). Adds `<meta name="referrer" content="no-referrer">` once.
 */
export function setNoReferrer(): void {
  if (typeof document === "undefined" || !document.head) return;
  if (document.head.querySelector('meta[name="referrer"][content="no-referrer"]')) return;
  const meta = document.createElement("meta");
  meta.name = "referrer";
  meta.content = "no-referrer";
  document.head.prepend(meta);
}
