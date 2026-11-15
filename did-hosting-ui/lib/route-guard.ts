/**
 * The console's one route guard, as a decision the root layout acts on.
 *
 * - `splash` — the saved session is still being looked for; show the splash
 *   rather than flash a signed-out page at a signed-in visitor.
 * - `redirect` — signed out on a page that needs a session: go to the
 *   sign-in page, which returns here afterwards (`?next=`).
 * - `expired` — the session ended under the operator. Keep the screen mounted
 *   (unsaved work stays on it) and prompt to sign in again over it.
 * - `render` — show the page.
 */
export type GuardDecision = "splash" | "redirect" | "expired" | "render";

/** Pages anyone may open. */
const PUBLIC_ROUTES = ["/login", "/enroll"];

export function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some((r) => pathname === r || pathname.startsWith(`${r}/`));
}

export function guardDecision(s: {
  pathname: string;
  restored: boolean;
  isAuthenticated: boolean;
  sessionExpired: boolean;
}): GuardDecision {
  if (isPublicRoute(s.pathname)) return "render";
  if (s.isAuthenticated) return "render";
  if (!s.restored) return "splash";
  if (s.sessionExpired) return "expired";
  return "redirect";
}
