import { useMemo } from "react";
import { View, Text, StyleSheet, ActivityIndicator, ScrollView } from "react-native";
import { Link } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { useApi } from "../components/ApiProvider";
import { useDomains } from "../components/DomainProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { LazyUsageChart } from "../components/LazyUsageChart";
import { ServiceOverviewPanel } from "../components/ServiceOverview";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { ACL_KEY } from "../components/acl/keys";
import { Button } from "../components/Button";
import { Heading } from "../components/Heading";
import { ErrorWithRetry, StaleMarker } from "../components/QueryState";
import { RequireAuth } from "../components/RequireAuth";
import { plural } from "../lib/plural";
import { useTrustTaskQuery } from "../lib/query";
import { QK } from "../lib/query-keys";
import { matchesDomain } from "../lib/domain";
import type { DidRecord } from "../lib/api";

export default function Dashboard() {
  return (
    <RequireAuth purpose="the dashboard">
      <DashboardBody />
    </RequireAuth>
  );
}

/** Per-domain totals over a DID list. */
function domainTotals(dids: DidRecord[]) {
  return {
    totalDids: dids.length,
    totalResolves: dids.reduce((s, d) => s + d.totalResolves, 0),
    // versionCount is the length of the current log chain; subtract 1 to
    // approximate "updates beyond initial creation". DIDs that haven't
    // uploaded a log yet (versionCount === 0) contribute 0.
    totalUpdates: dids.reduce((s, d) => s + Math.max(0, d.versionCount - 1), 0),
  };
}

function DashboardBody() {
  const { isAuthenticated, role } = useAuth();
  const api = useApi();
  const { currentDomain, domains } = useDomains();
  const isAdmin = role === "admin";
  // `server/config` and the server-wide `stats/get` are both admin-only on
  // the backend (config carries operator topology). Skipped for non-admins —
  // `config` only drives the daemon/standalone label, and the usage chart /
  // aggregate section is hidden whenever `serverStats` is absent. A failure
  // leaves them absent, as before. The keys are shared with the service
  // overview and settings, so the page asks for each once.
  const health = useTrustTaskQuery(QK.health, () => api.health());
  const configQuery = useTrustTaskQuery(
    QK.serverConfig,
    ({ background }) => api.getConfig({ background }),
    { enabled: isAuthenticated && isAdmin },
  );
  const config = configQuery.data;
  const statsQuery = useTrustTaskQuery(
    QK.serverStats,
    ({ background }) => api.getServerStats({ background }),
    { enabled: isAuthenticated && isAdmin },
  );
  const serverStats = statsQuery.data;
  const aclQuery = useTrustTaskQuery(ACL_KEY, () => api.listAcl(), {
    enabled: isAuthenticated && isAdmin,
  });
  const aclEntries = aclQuery.data?.entries ?? null;
  // An admin's pinned-domain totals: one `stats/get` for that domain, however
  // many DIDs it holds. "All domains" reads the server-wide aggregate instead.
  // Under the `stats` prefix, so whatever refreshes the stats refreshes it.
  const domainStatsQuery = useTrustTaskQuery(
    QK.domainStats(currentDomain),
    ({ background }) => api.getDomainStats(currentDomain ?? "", { background }),
    { enabled: isAuthenticated && isAdmin && currentDomain !== null },
  );
  // An owner has no aggregate to read: their own DIDs (bounded by their
  // quota) are the source of their per-domain cards.
  const didsQuery = useTrustTaskQuery(QK.allDids, () => api.listDids(), {
    enabled: isAuthenticated && !isAdmin,
  });
  const dids = didsQuery.data;

  const isDaemon = config?.deploymentMode === "daemon";

  const domainStats = useMemo(() => {
    if (currentDomain === null) return null;
    if (isAdmin) return domainStatsQuery.data ?? null;
    if (!dids) return null;
    // Legacy slots carry an empty `domain`; the shared matchesDomain helper
    // falls back to the DID's host segment so the per-domain numbers don't
    // read as zero before publish-time backfill tags them.
    return domainTotals(dids.filter((d) => matchesDomain(d, currentDomain)));
  }, [currentDomain, isAdmin, domainStatsQuery.data, dids]);

  // An owner's DIDs, one card per domain they host on.
  const ownerDomains = useMemo(() => {
    if (isAdmin || !dids) return null;
    const by = new Map<string, DidRecord[]>();
    for (const d of dids) {
      if (currentDomain !== null && !matchesDomain(d, currentDomain)) continue;
      const key = d.domain || "(no domain)";
      by.set(key, [...(by.get(key) ?? []), d]);
    }
    return [...by.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([domain, list]) => ({ domain, ...domainTotals(list) }));
  }, [isAdmin, dids, currentDomain]);

  // Owners whose scope is unrestricted ("All") are flagged for migration:
  // v0.7 grants new Owners a scoped default, but pre-existing rows keep
  // their `kind: "all"` shape until an admin tightens them. We count
  // locally rather than requiring a dedicated endpoint — listAcl already
  // returns the full set for admins.
  const allScopedOwnerCount = useMemo(() => {
    if (!aclEntries) return 0;
    return aclEntries.filter((e) => e.role === "owner" && (!e.domains || e.domains.kind === "all"))
      .length;
  }, [aclEntries]);

  return (
    <ScrollView style={styles.scroll} contentContainerStyle={styles.scrollContent}>
      <View style={styles.header}>
        <AffinidiLogo size={48} />
        <Heading style={styles.subtitle}>Decentralized Identity Hosting</Heading>
        <Text style={styles.domainCaption}>
          {currentDomain ? `Active domain: ${currentDomain}` : "Showing all domains"}
        </Text>
      </View>

      {isAdmin && allScopedOwnerCount > 0 && (
        <View style={styles.migrationBanner}>
          <Text style={styles.migrationTitle}>
            {plural(allScopedOwnerCount, "owner", "owners")} on unrestricted scope
          </Text>
          <Text style={styles.migrationBody}>
            These ACL entries still use the legacy “All domains” scope. Open Access Control to
            narrow each owner to specific domains and set a default.
          </Text>
          <Link href="/acl" asChild>
            <Button label="Review owners" style={styles.migrationButton} />
          </Link>
        </View>
      )}

      {health.error && !health.data ? (
        <View style={styles.section}>
          <ErrorWithRetry
            error={health.error}
            what="the control plane's status"
            onRetry={() => void health.refetch()}
          />
        </View>
      ) : health.data ? (
        <View style={styles.statusRow}>
          <View style={styles.card}>
            <Text style={styles.cardLabel}>Status</Text>
            <Text style={styles.statusOk}>{health.data.status}</Text>
          </View>
          <View style={styles.card}>
            <Text style={styles.cardLabel}>Version</Text>
            <Text style={styles.cardValue}>{health.data.version}</Text>
          </View>
          {isDaemon && (
            <View style={styles.card}>
              <Text style={styles.cardLabel}>Mode</Text>
              <Text style={styles.cardValue}>Daemon</Text>
            </View>
          )}
          {serverStats && (
            <>
              <View style={styles.card}>
                <Text style={styles.cardLabel}>
                  {domainStats ? `DIDs in ${currentDomain}` : "Total DIDs"}
                </Text>
                <Text style={styles.cardValueAccent}>
                  {(domainStats?.totalDids ?? serverStats.totalDids).toLocaleString()}
                </Text>
              </View>
              <View style={styles.card}>
                <Text style={styles.cardLabel}>Domains</Text>
                <Text style={styles.cardValue}>{domains.length.toLocaleString()}</Text>
              </View>
              <View style={styles.card}>
                <Text style={styles.cardLabel}>{domainStats ? "Resolves" : "Total Resolves"}</Text>
                <Text style={styles.cardValue}>
                  {(domainStats?.totalResolves ?? serverStats.totalResolves).toLocaleString()}
                </Text>
              </View>
              <View style={styles.card}>
                <Text style={styles.cardLabel}>{domainStats ? "Updates" : "Total Updates"}</Text>
                <Text style={styles.cardValue}>
                  {(domainStats?.totalUpdates ?? serverStats.totalUpdates).toLocaleString()}
                </Text>
              </View>
            </>
          )}
        </View>
      ) : (
        <ActivityIndicator color={colors.accent} size="large" />
      )}

      {/* Reads that failed with nothing to show: said, with a retry, rather
          than leaving the cards they feed silently missing. */}
      {[
        { q: statsQuery, what: "the statistics" },
        isAdmin
          ? { q: domainStatsQuery, what: "the statistics for this domain" }
          : { q: didsQuery, what: "your DIDs" },
        { q: aclQuery, what: "the access list" },
      ]
        .filter(({ q }) => q.error != null && q.data === undefined)
        .map(({ q, what }) => (
          <View key={what} style={styles.section}>
            <ErrorWithRetry error={q.error} what={what} onRetry={() => void q.refetch()} />
          </View>
        ))}

      {ownerDomains && (
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Heading level={2} style={styles.sectionTitle}>
              Your DIDs by domain
            </Heading>
            <StaleMarker
              updatedAt={didsQuery.updatedAt}
              error={didsQuery.error}
              onRetry={() => void didsQuery.refetch()}
            />
          </View>
          {ownerDomains.length === 0 ? (
            <View style={styles.emptyCard}>
              <Text style={styles.emptyText}>
                {currentDomain
                  ? `You have no DIDs on ${currentDomain} yet.`
                  : "You have no DIDs yet."}
              </Text>
              <Link href="/dids" asChild>
                <Button label="Create a DID" style={styles.migrationButton} />
              </Link>
            </View>
          ) : (
            <View style={styles.statusRow}>
              {ownerDomains.map((d) => (
                <View
                  key={d.domain}
                  style={[styles.card, styles.domainCard]}
                  role="region"
                  aria-label={d.domain}
                >
                  <Text style={styles.cardLabel}>{d.domain}</Text>
                  <Text style={styles.cardValueAccent}>{d.totalDids.toLocaleString()}</Text>
                  <Text style={styles.domainMeta}>
                    {plural(d.totalDids, "DID", "DIDs")} · {d.totalResolves.toLocaleString()}{" "}
                    resolves · {d.totalUpdates.toLocaleString()} updates
                  </Text>
                </View>
              ))}
            </View>
          )}
        </View>
      )}

      {/* Control-plane transports + service topology. Rendered in both
          modes: a daemon still has its own DID document advertising
          DIDComm / TSP, and the operator needs to see that here. The
          panel itself decides how much registry detail to show.
          Admin-only — `server/config` and `registry/list` need an admin,
          so rendering this for anyone else just yields a 403 error box. */}
      {isAdmin && (
        <View style={styles.section}>
          <Heading level={2} style={styles.sectionTitle}>
            {isDaemon ? "Control Plane" : "Service Topology"}
          </Heading>
          <ServiceOverviewPanel isDaemon={isDaemon} />
        </View>
      )}

      {/* Usage chart */}
      {serverStats && (
        <View style={styles.section}>
          <LazyUsageChart />
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: {
    flex: 1,
    backgroundColor: colors.bgPrimary,
  },
  scrollContent: {
    padding: spacing.xl,
    alignItems: "center",
    paddingBottom: spacing.xxxl,
  },
  container: {
    flex: 1,
    padding: spacing.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgPrimary,
  },
  header: {
    alignItems: "center",
    marginBottom: spacing.lg,
  },
  subtitle: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginTop: spacing.md,
    letterSpacing: 0.5,
  },
  section: {
    width: "100%",
    maxWidth: 1200,
    marginTop: spacing.xl,
  },
  sectionTitle: {
    fontSize: 18,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  statusRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.md,
    justifyContent: "center",
    marginBottom: spacing.lg,
    width: "100%",
    maxWidth: 1200,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    minWidth: 140,
    flex: 1,
    alignItems: "center",
  },
  sectionHeader: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    justifyContent: "space-between",
    gap: spacing.sm,
    marginBottom: spacing.md,
  },
  domainCard: {
    alignItems: "flex-start",
    minWidth: 200,
  },
  domainMeta: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginTop: spacing.xs,
  },
  emptyCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    alignItems: "flex-start",
    gap: spacing.md,
  },
  emptyText: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  errorCard: {
    backgroundColor: colors.errorBg,
    borderColor: colors.error,
    width: "100%",
    maxWidth: 1200,
    marginBottom: spacing.lg,
  },
  cardLabel: {
    fontSize: 11,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 1,
    marginBottom: spacing.xs,
  },
  cardValue: {
    fontSize: 18,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
  },
  cardValueAccent: {
    fontSize: 24,
    fontFamily: fonts.bold,
    color: colors.accent,
  },
  statusOk: {
    fontSize: 18,
    fontFamily: fonts.bold,
    color: colors.teal,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    fontSize: 14,
  },
  domainCaption: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
    marginTop: 4,
  },
  migrationBanner: {
    width: "100%",
    maxWidth: 1200,
    backgroundColor: "rgba(31, 229, 205, 0.08)",
    borderColor: colors.teal,
    borderWidth: 1,
    borderRadius: radii.lg,
    padding: spacing.lg,
    marginBottom: spacing.lg,
  },
  migrationTitle: {
    fontSize: 15,
    fontFamily: fonts.semibold,
    color: colors.teal,
    marginBottom: spacing.xs,
  },
  migrationBody: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 19,
    marginBottom: spacing.md,
  },
  migrationButton: {
    alignSelf: "flex-start",
    paddingHorizontal: spacing.lg,
    paddingVertical: 8,
    borderRadius: radii.sm,
  },
});
