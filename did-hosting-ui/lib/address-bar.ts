/**
 * Remove `name` from the page's query string in place, with
 * `history.replaceState`: the address bar and the current history entry stop
 * showing it, and nothing is reloaded or navigated. For a one-time secret in
 * a link (an enrolment invite token) that has already been read.
 *
 * No-op off the web (native builds have no `window.history`) or when the
 * parameter is absent.
 */
export function stripQueryParam(name: string): void {
  if (typeof window === "undefined") return;
  const { history, location } = window;
  if (!history?.replaceState || !location?.href) return;
  const url = new URL(location.href);
  if (!url.searchParams.has(name)) return;
  url.searchParams.delete(name);
  history.replaceState(history.state, "", `${url.pathname}${url.search}${url.hash}`);
}
