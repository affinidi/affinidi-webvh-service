import { useEffect, useMemo, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  ActivityIndicator,
  ScrollView,
} from "react-native";
import { Link } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { useApi } from "../components/ApiProvider";
import { useDomains } from "../components/DomainProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { UsageChart } from "../components/UsageChart";
import { ServiceOverviewPanel } from "../components/ServiceOverview";
import { colors, fonts, radii, spacing } from "../lib/theme";
import type {
  AclEntry,
  ControlPlaneConfig,
  DidRecord,
  HealthResponse,
  ServerStats,
} from "../lib/api";
import { matchesDomain } from "../lib/domain";

export default function Dashboard() {
  const { isAuthenticated, role } = useAuth();
  const api = useApi();
  const { currentDomain, domains } = useDomains();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [serverStats, setServerStats] = useState<ServerStats | null>(null);
  const [config, setConfig] = useState<ControlPlaneConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [aclEntries, setAclEntries] = useState<AclEntry[] | null>(null);
  // Per-domain stats are derived from the DID list. We only fetch it
  // when a specific domain is pinned — "All domains" reads the cheap
  // server-wide aggregate from /api/stats instead.
  const [dids, setDids] = useState<DidRecord[] | null>(null);

  const isDaemon = config?.deploymentMode === "daemon";
  const isAdmin = role === "admin";

  const domainStats = useMemo(() => {
    if (currentDomain === null || dids === null) return null;
    // Legacy slots pre-M-01 (and the historical bug where create
    // dropped the `domain` field) carry an empty `domain`. The shared
    // matchesDomain helper in lib/domain.ts falls back to the
    // did_id's host segment so the per-domain numbers don't read as
    // zero in the gap between an upgrade and publish-time backfill.
    const scoped = dids.filter((d) => matchesDomain(d, currentDomain));
    return {
      totalDids: scoped.length,
      totalResolves: scoped.reduce((s, d) => s + d.totalResolves, 0),
      // versionCount is the length of the current log chain; subtract 1
      // to approximate "updates beyond initial creation". DIDs that
      // haven't uploaded a log yet (versionCount === 0) contribute 0.
      totalUpdates: scoped.reduce(
        (s, d) => s + Math.max(0, d.versionCount - 1),
        0,
      ),
    };
  }, [currentDomain, dids]);

  // Owners whose scope is unrestricted ("All") are flagged for migration:
  // v0.7 grants new Owners a scoped default, but pre-existing rows keep
  // their `kind: "all"` shape until an admin tightens them. We count
  // locally rather than requiring a dedicated endpoint — listAcl already
  // returns the full set for admins.
  const allScopedOwnerCount = useMemo(() => {
    if (!aclEntries) return 0;
    return aclEntries.filter(
      (e) =>
        e.role === "owner" && (!e.domains || e.domains.kind === "all"),
    ).length;
  }, [aclEntries]);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch((e) => setError(e.message));
  }, [api]);

  useEffect(() => {
    if (!isAuthenticated) return;
    api
      .getServerStats()
      .then(setServerStats)
      .catch(() => {});
    api
      .getConfig()
      .then(setConfig)
      .catch(() => {});
  }, [isAuthenticated, api]);

  useEffect(() => {
    if (!isAuthenticated || !isAdmin) return;
    api
      .listAcl()
      .then((res) => setAclEntries(res.entries))
      .catch(() => setAclEntries(null));
  }, [api, isAuthenticated, isAdmin]);

  // When a domain is pinned, pull the DID list so we can derive
  // per-domain stat cards. "All domains" doesn't need this — the
  // server-wide aggregate from /api/stats is shown instead.
  useEffect(() => {
    if (!isAuthenticated || currentDomain === null) {
      setDids(null);
      return;
    }
    let cancelled = false;
    api
      .listDids()
      .then((res) => {
        if (!cancelled) setDids(res);
      })
      .catch(() => {
        if (!cancelled) setDids(null);
      });
    return () => {
      cancelled = true;
    };
  }, [api, isAuthenticated, currentDomain]);

  if (!isAuthenticated) {
    return (
      <View style={styles.container}>
        <AffinidiLogo size={48} />
        <Text style={styles.subtitle}>Decentralized Identity Hosting</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.buttonPrimary}>
            <Text style={styles.buttonPrimaryText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  return (
    <ScrollView
      style={styles.scroll}
      contentContainerStyle={styles.scrollContent}
    >
      <View style={styles.header}>
        <AffinidiLogo size={48} />
        <Text style={styles.subtitle}>Decentralized Identity Hosting</Text>
        <Text style={styles.domainCaption}>
          {currentDomain
            ? `Active domain: ${currentDomain}`
            : "Showing all domains"}
        </Text>
      </View>

      {isAdmin && allScopedOwnerCount > 0 && (
        <View style={styles.migrationBanner}>
          <Text style={styles.migrationTitle}>
            {allScopedOwnerCount} owner
            {allScopedOwnerCount === 1 ? "" : "s"} on unrestricted scope
          </Text>
          <Text style={styles.migrationBody}>
            These ACL entries still use the legacy "All domains" scope. Open
            Access Control to narrow each owner to specific domains and set a
            default.
          </Text>
          <Link href="/acl" asChild>
            <Pressable style={styles.migrationButton}>
              <Text style={styles.migrationButtonText}>Review owners</Text>
            </Pressable>
          </Link>
        </View>
      )}

      {error ? (
        <View style={[styles.card, styles.errorCard]}>
          <Text style={styles.errorText}>Server unreachable: {error}</Text>
        </View>
      ) : health ? (
        <View style={styles.statusRow}>
          <View style={styles.card}>
            <Text style={styles.cardLabel}>Status</Text>
            <Text style={styles.statusOk}>{health.status}</Text>
          </View>
          <View style={styles.card}>
            <Text style={styles.cardLabel}>Version</Text>
            <Text style={styles.cardValue}>{health.version}</Text>
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
                <Text style={styles.cardLabel}>
                  {domainStats ? "Resolves" : "Total Resolves"}
                </Text>
                <Text style={styles.cardValue}>
                  {(domainStats?.totalResolves ?? serverStats.totalResolves).toLocaleString()}
                </Text>
              </View>
              <View style={styles.card}>
                <Text style={styles.cardLabel}>
                  {domainStats ? "Updates" : "Total Updates"}
                </Text>
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

      {/* Control-plane transports + service topology. Rendered in both
          modes: a daemon still has its own DID document advertising
          DIDComm / TSP, and the operator needs to see that here. The
          panel itself decides how much registry detail to show.
          Admin-only — `GET /api/services/overview` is behind AdminAuth,
          so rendering this for anyone else just yields a 403 error box. */}
      {isAdmin && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>
            {isDaemon ? "Control Plane" : "Service Topology"}
          </Text>
          <ServiceOverviewPanel isDaemon={isDaemon} />
        </View>
      )}

      {/* Usage chart */}
      {serverStats && (
        <View style={styles.section}>
          <UsageChart />
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
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 14,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
    // Visual breathing room from the subtitle above — without this
    // the button hugs "Decentralized Identity Hosting" with no gap.
    marginTop: spacing.xl,
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontSize: 16,
    fontFamily: fonts.semibold,
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
    backgroundColor: colors.teal,
    paddingHorizontal: spacing.lg,
    paddingVertical: 8,
    borderRadius: radii.sm,
  },
  migrationButtonText: {
    fontSize: 13,
    fontFamily: fonts.semibold,
    color: colors.bgPrimary,
  },
});
