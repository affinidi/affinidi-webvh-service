/** The API base the wallet talks to on the page's behalf (SIOPv2 login,
 *  step-up). The UI is served same-origin with the did-hosting-control API at
 *  `/api`, so the default resolves the wallet's `${baseUrl}/trust-tasks` and
 *  `${baseUrl}/auth/challenge` without configuration. Override with
 *  `EXPO_PUBLIC_API_BASE` if the API is on a separate origin. */
export function getApiBase(): string {
  if (process.env.EXPO_PUBLIC_API_BASE) return process.env.EXPO_PUBLIC_API_BASE;
  return (typeof window !== "undefined" ? window.location.origin : "") + "/api";
}
