/**
 * Whether this server's DID lists the services wallet sign-in needs
 * (`GET /api/sign-in/readiness`, the control plane's self-check).
 *
 * A server DID without `SignInPortal` or `TrustTaskHTTPS` still answers
 * `auth/oob/request`, but every wallet then says "This code can't be used".
 * So the login page asks first, and when the answer is `not-set-up` it shows
 * why and opens the older logins, as it does when `auth/oob` answers 503.
 *
 * `WebVHHosting` is only recommended (`missingRecommended`): without it a
 * wallet that does not know this server won't offer to add it, but sign-in
 * works. The page shows nothing for it.
 *
 * Anything other than a clear `not-set-up` (an older control plane without
 * the route, a network error, a check that has not run or could not resolve
 * the DID) keeps the sign-in offered: a transient failure must not hide it.
 *
 * Free of `react-native` so the test runner can reach it.
 */

import { getApiBase } from "./api-base";

/** The services sign-in cannot work without, in the order the note lists them. */
export const REQUIRED_SERVICES = ["SignInPortal", "TrustTaskHTTPS"] as const;
export type RequiredService = (typeof REQUIRED_SERVICES)[number];
/** Services the self-check recommends; never a reason to hide sign-in. */
export const RECOMMENDED_SERVICES = ["WebVHHosting"] as const;
export type RecommendedService = (typeof RECOMMENDED_SERVICES)[number];

export type SignInReadiness =
  | { walletSignIn: "ready"; missingRecommended: RecommendedService[] }
  | { walletSignIn: "unknown" }
  | {
      walletSignIn: "not-set-up";
      missingServices: RequiredService[];
      missingRecommended: RecommendedService[];
    };

const UNKNOWN: SignInReadiness = { walletSignIn: "unknown" };

/** Read a response body; anything unexpected is `unknown`. */
export function parseReadiness(body: unknown): SignInReadiness {
  if (typeof body !== "object" || body === null) return UNKNOWN;
  const b = body as {
    walletSignIn?: unknown;
    missingServices?: unknown;
    missingRecommended?: unknown;
  };
  const recommended = new Set(Array.isArray(b.missingRecommended) ? b.missingRecommended : []);
  const missingRecommended = RECOMMENDED_SERVICES.filter((s) => recommended.has(s));
  if (b.walletSignIn === "ready") return { walletSignIn: "ready", missingRecommended };
  if (b.walletSignIn === "not-set-up" && Array.isArray(b.missingServices)) {
    const named = new Set(b.missingServices);
    const missingServices = REQUIRED_SERVICES.filter((s) => named.has(s));
    if (missingServices.length > 0) {
      return { walletSignIn: "not-set-up", missingServices, missingRecommended };
    }
  }
  return UNKNOWN;
}

/** Whether the page should offer wallet sign-in: yes unless clearly not set up. */
export function offersWalletSignIn(r: SignInReadiness): boolean {
  return r.walletSignIn !== "not-set-up";
}

function listInProse(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/** The note the login page shows when wallet sign-in is not set up, else null.
 *  Names only the required services: a missing `WebVHHosting` gets no note. */
export function notSetUpNote(r: SignInReadiness): string | null {
  if (r.walletSignIn !== "not-set-up") return null;
  return (
    "Wallet sign-in isn't set up on this server yet: its DID doesn't list " +
    `${listInProse(r.missingServices)}.`
  );
}

/** Ask the control plane. Never throws: a failure is `unknown`. */
export async function fetchSignInReadiness(
  fetchImpl: typeof fetch = fetch,
  base: string = getApiBase(),
): Promise<SignInReadiness> {
  try {
    const res = await fetchImpl(`${base}/sign-in/readiness`, {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return UNKNOWN;
    return parseReadiness(await res.json());
  } catch {
    return UNKNOWN;
  }
}
