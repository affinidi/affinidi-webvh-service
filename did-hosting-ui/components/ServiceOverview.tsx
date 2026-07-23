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
import {
  ServiceBadges,
  SERVICE_TYPE_DIDCOMM,
  SERVICE_TYPE_TSP,
} from "./ServiceBadges";
import { ControlLink } from "./ControlLink";
import { AgentNameChips } from "./AgentNameChips";
import { colors, fonts, radii, spacing } from "../lib/theme";
import type { ServiceOverview, ServiceInfo } from "../lib/api";
import { useAgentNames } from "../lib/use-agent-names";

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

/**
 * One transport row on the control-plane card: what config enables versus
 * what the control DID's document advertises to peers.
 *
 * The two can disagree, and each direction is a distinct real fault:
 * enabled-but-unadvertised means peers never learn they can reach us that
 * way; advertised-but-disabled means they try and get nothing. We only
 * claim a mismatch when we actually resolved the document — `advertised`
 * is `undefined` when the DID wouldn't resolve, and silence beats a false
 * alarm there.
 */
function TransportRow({
  label,
  enabled,
  advertised,
}: {
  label: string;
  enabled: boolean;
  advertised: boolean | undefined;
}) {
  const mismatch = advertised !== undefined && enabled !== advertised;

  return (
    <View style={styles.transportRow}>
      <Text style={styles.transportName}>{label}</Text>
      <View style={[styles.flagBadge, enabled ? styles.flagOn : styles.flagOff]}>
        <Text style={styles.flagText}>{enabled ? "enabled" : "disabled"}</Text>
      </View>
      {advertised === undefined ? (
        <Text style={styles.transportUnknown}>advertised: unknown</Text>
      ) : (
        <View
          style={[
            styles.flagBadge,
            advertised ? styles.flagOn : styles.flagOff,
            mismatch && styles.flagMismatch,
          ]}
        >
          <Text style={styles.flagText}>
            {advertised ? "advertised" : "not advertised"}
          </Text>
        </View>
      )}
    </View>
  );
}

/** The human-readable consequence of an enabled/advertised mismatch. */
function mismatchWarning(
  label: string,
  enabled: boolean,
  advertised: boolean,
): string | null {
  if (enabled && !advertised) {
    return `${label} is enabled but the control plane's DID document has no ${label} service — peers cannot discover this transport.`;
  }
  if (!enabled && advertised) {
    return `The control plane's DID document advertises ${label}, but ${label} is disabled — peers that try this transport will fail.`;
  }
  return null;
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

function ServiceCard({
  service,
  agentNames,
}: {
  service: ServiceInfo;
  agentNames: string[];
}) {
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

      {/* The DID is truncated for width, so the full value goes to the chips
          via `didId` — they need the authority, not the ellipsis. */}
      {shortDid && (
        <Text style={styles.serviceDid} numberOfLines={1}>{shortDid}</Text>
      )}
      {agentNames.length > 0 && (
        <View style={styles.serviceNamesRow}>
          <AgentNameChips names={agentNames} didId={did} size="sm" />
        </View>
      )}

      {/* What this instance's DID document advertises. Cached on the
          registry record; refreshed at register + health check. */}
      <ServiceBadges services={service.advertisedServices} />

      {/* And what actually carried traffic, per direction. */}
      <ControlLink
        lastInboundTransport={service.lastInboundTransport}
        lastInboundAt={service.lastInboundAt}
        lastOutboundTransport={service.lastOutboundTransport}
        lastOutboundAt={service.lastOutboundAt}
      />

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

/**
 * An empty registry means different things per deployment.
 *
 * On a standalone control plane it means nothing has connected yet \u2014 the
 * operator has work to do. On a daemon it is the normal, self-contained
 * state (see CLAUDE.md), so saying "no services connected" would read as a
 * fault rather than the expected shape.
 */
function EmptyState({ isDaemon }: { isDaemon: boolean }) {
  if (isDaemon) {
    return (
      <View style={styles.emptyCard}>
        <Text style={styles.emptyIcon}>{"\u2713"}</Text>
        <Text style={styles.emptyTitle}>Self-contained daemon</Text>
        <Text style={styles.emptyHint}>
          Server, witness, and watcher run in this process \u2014 there are no
          remote instances to register. Registering one is supported but
          unusual; use a standalone control plane to manage remote services.
        </Text>
      </View>
    );
  }
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

/**
 * @param isDaemon - all-in-one deployment. The control-plane card renders
 *   either way; this only changes how an empty registry is explained and
 *   suppresses the service-count tiles, which are always zero there.
 */
export function ServiceOverviewPanel({
  isDaemon = false,
}: {
  isDaemon?: boolean;
}) {
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

  // Above the early returns, so the hook order stays fixed. The panel polls
  // every 5s; the lookup only re-fires when the set of DIDs actually changes.
  const agentNames = useAgentNames((data?.services ?? []).map((s) => s.did));

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

  // `undefined` — not just `false` — when the control DID wouldn't resolve,
  // so `TransportRow` can stay quiet rather than reporting a false mismatch.
  const advertised = control.advertisedServices;
  const advertisedDidcomm = advertised?.includes(SERVICE_TYPE_DIDCOMM);
  const advertisedTsp = advertised?.includes(SERVICE_TYPE_TSP);

  const transportWarnings =
    advertised === undefined
      ? []
      : ([
          mismatchWarning("DIDComm", control.didcommEnabled, !!advertisedDidcomm),
          mismatchWarning("TSP", control.tspEnabled, !!advertisedTsp),
        ].filter(Boolean) as string[]);

  // A daemon that *has* registered remote instances still gets the full
  // registry view — key off the data, not the deployment mode alone.
  const showRegistry = !isDaemon || services.length > 0;

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
        </View>

        {/* Transports: config-enabled vs DID-document-advertised. */}
        <View style={styles.transportsBlock}>
          <TransportRow
            label="DIDComm"
            enabled={control.didcommEnabled}
            advertised={advertisedDidcomm}
          />
          <TransportRow
            label="TSP"
            enabled={control.tspEnabled}
            advertised={advertisedTsp}
          />
          {transportWarnings.map((w) => (
            <View key={w} style={styles.transportWarnBanner}>
              <Text style={styles.transportWarnIcon}>{"⚠"}</Text>
              <Text style={styles.transportWarnText}>{w}</Text>
            </View>
          ))}
          {control.advertisedServices === undefined && (
            <Text style={styles.transportUnknownNote}>
              {control.serverDid
                ? "Could not resolve the control plane's DID document — advertised services unknown."
                : "No control-plane DID configured — nothing is advertised to peers."}
            </Text>
          )}
        </View>

        {/* DID methods compiled into this binary. Empty list = misbuild
            — surface as a red banner so the operator can't miss it. */}
        <View style={styles.methodsRow}>
          <Text style={styles.methodsLabel}>DID methods</Text>
          {control.enabledMethods.length === 0 ? (
            <View style={styles.methodsEmptyBanner}>
              <Text style={styles.methodsEmptyIcon}>{"⚠"}</Text>
              <Text style={styles.methodsEmptyText}>
                No DID methods compiled in — every DID op will fail.
                Rebuild with at least one of the {"`method-*`"} cargo
                features (e.g. {"`--features method-webvh,method-web`"}).
              </Text>
            </View>
          ) : (
            <View style={styles.methodsChips}>
              {control.enabledMethods.map((m) => (
                <View key={m} style={styles.methodChip}>
                  <Text style={styles.methodChipText}>did:{m}</Text>
                </View>
              ))}
            </View>
          )}
        </View>
      </View>

      {/* Aggregate summary. The service-count tiles are meaningless on a
          daemon with an empty registry — they'd read a constant zero — but
          the DID / resolve / update totals are real in both modes. */}
      <View style={styles.summaryRow}>
        {showRegistry && (
          <>
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
          </>
        )}
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
        <EmptyState isDaemon={isDaemon} />
      ) : (
        <>
          {servers.length > 0 && (
            <ServiceGroup
              label="Servers"
              services={servers}
              agentNames={agentNames}
            />
          )}
          {witnesses.length > 0 && (
            <ServiceGroup
              label="Witnesses"
              services={witnesses}
              agentNames={agentNames}
            />
          )}
          {watchers.length > 0 && (
            <ServiceGroup
              label="Watchers"
              services={watchers}
              agentNames={agentNames}
            />
          )}
        </>
      )}
    </View>
  );
}

function ServiceGroup({
  label,
  services,
  agentNames,
}: {
  label: string;
  services: ServiceInfo[];
  agentNames: Record<string, string[]>;
}) {
  return (
    <View style={styles.group}>
      <Text style={styles.groupTitle}>
        {label}{" "}
        <Text style={styles.groupCount}>({services.length})</Text>
      </Text>
      {services.map((s) => (
        <ServiceCard
          key={s.instanceId}
          service={s}
          agentNames={agentNames[s.did ?? ""] ?? []}
        />
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    width: "100%",
    maxWidth: 1200,
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
  methodsRow: {
    marginTop: spacing.md,
    paddingTop: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.border,
    gap: spacing.sm,
  },
  methodsLabel: {
    fontSize: 10,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.8,
  },
  methodsChips: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.xs,
  },
  methodChip: {
    backgroundColor: colors.tealMuted,
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 3,
  },
  methodChipText: {
    fontSize: 11,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
  },
  methodsEmptyBanner: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: spacing.sm,
    backgroundColor: colors.errorBg,
    borderWidth: 1,
    borderColor: colors.error,
    borderRadius: radii.sm,
    padding: spacing.sm,
  },
  methodsEmptyIcon: {
    fontSize: 16,
    color: colors.error,
    marginTop: 1,
  },
  methodsEmptyText: {
    flex: 1,
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.error,
    lineHeight: 18,
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
  /** Outlines the *advertised* badge when it disagrees with config. */
  flagMismatch: {
    borderWidth: 1,
    borderColor: colors.warning,
  },
  flagText: {
    fontSize: 10,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },

  // Transports (enabled vs advertised)
  transportsBlock: {
    marginTop: spacing.sm,
    gap: 6,
  },
  transportRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    flexWrap: "wrap",
  },
  transportName: {
    minWidth: 70,
    fontSize: 12,
    fontFamily: fonts.semibold,
    color: colors.textSecondary,
  },
  transportUnknown: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    fontStyle: "italic",
  },
  transportUnknownNote: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    fontStyle: "italic",
    marginTop: 2,
  },
  transportWarnBanner: {
    flexDirection: "row",
    gap: 6,
    backgroundColor: "rgba(255, 181, 71, 0.12)",
    borderRadius: radii.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: 6,
    marginTop: 2,
  },
  transportWarnIcon: {
    fontSize: 12,
    color: colors.warning,
    marginTop: 1,
  },
  transportWarnText: {
    flex: 1,
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.warning,
    lineHeight: 18,
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
  serviceNamesRow: {
    marginBottom: spacing.sm,
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
