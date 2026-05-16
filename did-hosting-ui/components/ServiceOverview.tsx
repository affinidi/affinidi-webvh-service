import { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  ActivityIndicator,
  ScrollView,
} from "react-native";
import { useApi } from "./ApiProvider";
import { colors, fonts, radii, spacing } from "../lib/theme";
import type { ServiceOverview, ServiceInfo } from "../lib/api";

const STATUS_COLORS: Record<string, string> = {
  active: colors.teal,
  degraded: colors.warning,
  unreachable: colors.error,
};

const TYPE_LABELS: Record<string, string> = {
  server: "Server",
  witness: "Witness",
  watcher: "Watcher",
};

function timeAgo(epoch: number | null): string {
  if (!epoch) return "never";
  const secs = Math.floor(Date.now() / 1000) - epoch;
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function StatusDot({ status }: { status: string }) {
  const color = STATUS_COLORS[status] ?? colors.textTertiary;
  return (
    <View
      style={[styles.dot, { backgroundColor: color }]}
    />
  );
}

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLORS[status] ?? colors.textTertiary;
  return (
    <View style={[styles.badge, { borderColor: color }]}>
      <StatusDot status={status} />
      <Text style={[styles.badgeText, { color }]}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Text>
    </View>
  );
}

function TypeBadge({ type }: { type: string }) {
  return (
    <View style={styles.typeBadge}>
      <Text style={styles.typeBadgeText}>
        {TYPE_LABELS[type] ?? type}
      </Text>
    </View>
  );
}

function StatValue({ label, value }: { label: string; value: string | number }) {
  return (
    <View style={styles.statItem}>
      <Text style={styles.statLabel}>{label}</Text>
      <Text style={styles.statValue}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </Text>
    </View>
  );
}

function ServiceCard({ service }: { service: ServiceInfo }) {
  const did = service.did;
  const shortDid = did
    ? did.length > 40
      ? `${did.slice(0, 20)}...${did.slice(-12)}`
      : did
    : null;

  return (
    <View style={styles.serviceCard}>
      <View style={styles.serviceHeader}>
        <View style={styles.serviceHeaderLeft}>
          <TypeBadge type={service.serviceType} />
          <StatusBadge status={service.status} />
        </View>
        {service.label && (
          <Text style={styles.serviceLabel}>{service.label}</Text>
        )}
      </View>

      <Text style={styles.serviceUrl} numberOfLines={1}>{service.url}</Text>

      {shortDid && (
        <Text style={styles.serviceDid} numberOfLines={1}>{shortDid}</Text>
      )}

      <View style={styles.serviceMetaRow}>
        <Text style={styles.metaText}>
          Registered {timeAgo(service.registeredAt)}
        </Text>
        <Text style={styles.metaSep}>{"\u00B7"}</Text>
        <Text style={styles.metaText}>
          Health check {timeAgo(service.lastHealthCheck)}
        </Text>
      </View>

      {service.stats && (
        <View style={styles.serviceStatsRow}>
          <StatValue label="DIDs" value={service.stats.totalDids} />
          <StatValue label="Resolves" value={service.stats.totalResolves} />
          <StatValue label="Updates" value={service.stats.totalUpdates} />
          <StatValue
            label="Last Active"
            value={timeAgo(
              service.stats.lastResolvedAt ?? service.stats.lastUpdatedAt,
            )}
          />
        </View>
      )}
    </View>
  );
}

function EmptyState() {
  return (
    <View style={styles.emptyCard}>
      <Text style={styles.emptyIcon}>{"\u26A1"}</Text>
      <Text style={styles.emptyTitle}>No services connected</Text>
      <Text style={styles.emptyHint}>
        Start a webvh-server or webvh-witness with a control_url pointing
        to this control plane, or add instances in config.toml under
        [registry.instances].
      </Text>
    </View>
  );
}

export function ServiceOverviewPanel() {
  const api = useApi();
  const [data, setData] = useState<ServiceOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api
      .getServicesOverview()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, [refresh]);

  if (loading && !data) {
    return (
      <View style={styles.loadingBox}>
        <ActivityIndicator color={colors.accent} />
      </View>
    );
  }

  if (error && !data) {
    return (
      <View style={styles.errorBox}>
        <Text style={styles.errorText}>{error}</Text>
        <Pressable style={styles.retryButton} onPress={refresh}>
          <Text style={styles.retryText}>Retry</Text>
        </Pressable>
      </View>
    );
  }

  if (!data) return null;

  const { control, aggregate, services } = data;

  // Group by type
  const servers = services.filter((s) => s.serviceType === "server");
  const witnesses = services.filter((s) => s.serviceType === "witness");
  const watchers = services.filter((s) => s.serviceType === "watcher");

  return (
    <View style={styles.container}>
      {/* Control plane header card */}
      <View style={styles.controlCard}>
        <View style={styles.controlHeader}>
          <Text style={styles.controlTitle}>Control Plane</Text>
          <Text style={styles.versionBadge}>v{control.version}</Text>
        </View>
        <View style={styles.controlMeta}>
          {control.publicUrl && (
            <Text style={styles.controlUrl}>{control.publicUrl}</Text>
          )}
          <View style={styles.controlFlags}>
            <View style={[styles.flagBadge, control.didcommEnabled ? styles.flagOn : styles.flagOff]}>
              <Text style={styles.flagText}>DIDComm</Text>
            </View>
          </View>
        </View>
      </View>

      {/* Aggregate summary */}
      <View style={styles.summaryRow}>
        <View style={styles.summaryCard}>
          <Text style={styles.summaryValue}>{aggregate.totalServices}</Text>
          <Text style={styles.summaryLabel}>Services</Text>
        </View>
        <View style={styles.summaryCard}>
          <Text style={[styles.summaryValue, { color: colors.teal }]}>
            {aggregate.activeServices}
          </Text>
          <Text style={styles.summaryLabel}>Active</Text>
        </View>
        {aggregate.degradedServices > 0 && (
          <View style={styles.summaryCard}>
            <Text style={[styles.summaryValue, { color: colors.warning }]}>
              {aggregate.degradedServices}
            </Text>
            <Text style={styles.summaryLabel}>Degraded</Text>
          </View>
        )}
        {aggregate.unreachableServices > 0 && (
          <View style={styles.summaryCard}>
            <Text style={[styles.summaryValue, { color: colors.error }]}>
              {aggregate.unreachableServices}
            </Text>
            <Text style={styles.summaryLabel}>Unreachable</Text>
          </View>
        )}
        <View style={styles.summaryCard}>
          <Text style={[styles.summaryValue, { color: colors.accent }]}>
            {aggregate.totalDids.toLocaleString()}
          </Text>
          <Text style={styles.summaryLabel}>Total DIDs</Text>
        </View>
        <View style={styles.summaryCard}>
          <Text style={styles.summaryValue}>
            {aggregate.totalResolves.toLocaleString()}
          </Text>
          <Text style={styles.summaryLabel}>Resolves</Text>
        </View>
        <View style={styles.summaryCard}>
          <Text style={styles.summaryValue}>
            {aggregate.totalUpdates.toLocaleString()}
          </Text>
          <Text style={styles.summaryLabel}>Updates</Text>
        </View>
      </View>

      {/* Service groups */}
      {services.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          {servers.length > 0 && (
            <ServiceGroup label="Servers" services={servers} />
          )}
          {witnesses.length > 0 && (
            <ServiceGroup label="Witnesses" services={witnesses} />
          )}
          {watchers.length > 0 && (
            <ServiceGroup label="Watchers" services={watchers} />
          )}
        </>
      )}
    </View>
  );
}

function ServiceGroup({
  label,
  services,
}: {
  label: string;
  services: ServiceInfo[];
}) {
  return (
    <View style={styles.group}>
      <Text style={styles.groupTitle}>
        {label}{" "}
        <Text style={styles.groupCount}>({services.length})</Text>
      </Text>
      {services.map((s) => (
        <ServiceCard key={s.instanceId} service={s} />
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    width: "100%",
    maxWidth: 800,
  },
  loadingBox: {
    padding: spacing.xxl,
    alignItems: "center",
  },
  errorBox: {
    padding: spacing.xl,
    alignItems: "center",
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    fontSize: 14,
    marginBottom: spacing.md,
  },
  retryButton: {
    borderColor: colors.accent,
    borderWidth: 1,
    borderRadius: radii.sm,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.sm,
  },
  retryText: {
    fontFamily: fonts.semibold,
    color: colors.accent,
    fontSize: 13,
  },

  // Control plane card
  controlCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    marginBottom: spacing.md,
  },
  controlHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: spacing.sm,
  },
  controlTitle: {
    fontSize: 16,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
  },
  versionBadge: {
    fontSize: 11,
    fontFamily: fonts.mono,
    color: colors.textTertiary,
    backgroundColor: colors.bgTertiary,
    borderRadius: 4,
    paddingHorizontal: 6,
    paddingVertical: 2,
    overflow: "hidden",
  },
  controlMeta: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  controlUrl: {
    fontSize: 12,
    fontFamily: fonts.mono,
    color: colors.textSecondary,
  },
  controlFlags: {
    flexDirection: "row",
    gap: spacing.xs,
  },
  flagBadge: {
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  flagOn: {
    backgroundColor: colors.tealMuted,
  },
  flagOff: {
    backgroundColor: colors.errorBg,
  },
  flagText: {
    fontSize: 10,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },

  // Summary row
  summaryRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.sm,
    marginBottom: spacing.lg,
  },
  summaryCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.md,
    minWidth: 90,
    flex: 1,
    alignItems: "center",
  },
  summaryValue: {
    fontSize: 22,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
  },
  summaryLabel: {
    fontSize: 10,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.8,
    marginTop: 2,
  },

  // Service groups
  group: {
    marginBottom: spacing.lg,
  },
  groupTitle: {
    fontSize: 14,
    fontFamily: fonts.semibold,
    color: colors.textSecondary,
    marginBottom: spacing.sm,
    textTransform: "uppercase",
    letterSpacing: 1,
  },
  groupCount: {
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },

  // Service card
  serviceCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    marginBottom: spacing.sm,
  },
  serviceHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: spacing.sm,
  },
  serviceHeaderLeft: {
    flexDirection: "row",
    gap: spacing.sm,
    alignItems: "center",
  },
  serviceLabel: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
  },
  serviceUrl: {
    fontSize: 12,
    fontFamily: fonts.mono,
    color: colors.textSecondary,
    marginBottom: 4,
  },
  serviceDid: {
    fontSize: 11,
    fontFamily: fonts.mono,
    color: colors.textTertiary,
    marginBottom: spacing.sm,
  },
  serviceMetaRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    marginBottom: spacing.sm,
  },
  metaText: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  metaSep: {
    fontSize: 11,
    color: colors.textTertiary,
  },
  serviceStatsRow: {
    flexDirection: "row",
    gap: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.border,
    paddingTop: spacing.sm,
  },
  statItem: {
    flex: 1,
    alignItems: "center",
  },
  statLabel: {
    fontSize: 10,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.5,
    marginBottom: 2,
  },
  statValue: {
    fontSize: 14,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
  },

  // Status indicators
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  badge: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
    borderWidth: 1,
    borderRadius: 4,
    paddingHorizontal: 6,
    paddingVertical: 2,
  },
  badgeText: {
    fontSize: 11,
    fontFamily: fonts.semibold,
  },
  typeBadge: {
    backgroundColor: colors.bgTertiary,
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  typeBadgeText: {
    fontSize: 11,
    fontFamily: fonts.bold,
    color: colors.accent,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },

  // Empty state
  emptyCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    borderStyle: "dashed",
    padding: spacing.xxl,
    alignItems: "center",
  },
  emptyIcon: {
    fontSize: 32,
    marginBottom: spacing.md,
  },
  emptyTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textSecondary,
    marginBottom: spacing.sm,
  },
  emptyHint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    textAlign: "center",
    maxWidth: 400,
    lineHeight: 20,
  },
});
