/**
 * Query keys for reads more than one screen makes, so they share one cache
 * entry and one request (`lib/query.ts`). A key's prefix is what a mutation
 * invalidates: `["stats"]` refreshes every stats read.
 */
export const QK = {
  health: ["health"] as const,
  /** `server/config` — the dashboard, the service overview and settings. */
  serverConfig: ["server", "config"] as const,
  /** Server-wide `stats/get` — the dashboard and the service overview. */
  serverStats: ["stats", "server"] as const,
  /** `registry/list` — the service overview and the servers screen. */
  registry: ["registry"] as const,
  identityGenerations: ["identity", "generations"] as const,
  /** Every DID the caller sees — an owner's dashboard cards. */
  allDids: ["dids", "all"] as const,
  /** One domain's `stats/get` totals — the dashboard's pinned-domain cards. */
  domainStats: (domain: string | null) => ["stats", "domain", domain] as const,
};
