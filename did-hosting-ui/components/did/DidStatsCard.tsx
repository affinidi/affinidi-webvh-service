import { ActivityIndicator, StyleSheet, Text, View } from "react-native";

import type { DidDetailResponse, DidStats } from "../../lib/api";
import { colors, fonts, spacing } from "../../lib/theme";
import { formatDate } from "../../lib/time";
import { Card } from "../Card";
import { Heading } from "../Heading";
import { didStyles } from "./styles";
import { Term, type GlossaryKey } from "../Term";

/** Resolve and update counts for this DID. */
export function DidStatsCard({
  stats,
  error,
}: {
  stats: DidStats | undefined;
  error: string | null;
}) {
  return (
    <Card title="Statistics" style={didStyles.card}>
      {error ? (
        <Text style={didStyles.error} role="alert">
          {error}
        </Text>
      ) : stats ? (
        <View style={styles.grid}>
          <Stat value={stats.totalResolves.toLocaleString()} label="Resolves" big />
          <Stat value={stats.totalUpdates.toLocaleString()} label="Updates" big />
          <Stat
            value={formatDate(stats.lastResolvedAt, { withTime: true })}
            label="Last Resolved"
          />
          <Stat value={formatDate(stats.lastUpdatedAt, { withTime: true })} label="Last Updated" />
        </View>
      ) : (
        <ActivityIndicator color={colors.accent} aria-label="Loading statistics" />
      )}
    </Card>
  );
}

function Stat({ value, label, big }: { value: string; label: string; big?: boolean }) {
  return (
    <View style={styles.item}>
      <Text style={big ? styles.value : styles.small}>{value}</Text>
      <Text style={styles.label}>{label}</Text>
    </View>
  );
}

/** What the log says about this DID: version, method, options. */
export function DidDetailsCard({ detail }: { detail: DidDetailResponse }) {
  const log = detail.log;
  if (!log) return null;
  const method = detail.method ?? log.method;
  return (
    <Card title="DID Details" style={didStyles.card}>
      <View style={styles.details}>
        <Detail label="Version" value={log.latestVersionId ?? "-"} />
        {log.latestVersionTime && (
          <Detail
            label="Version Time"
            value={formatDate(log.latestVersionTime, { withTime: true })}
          />
        )}
        {method && <Detail label="Method" value={method} mono />}
        {detail.domain && <Detail label="Domain" value={detail.domain} mono />}
        <Detail label="Log Entries" value={log.logEntryCount.toLocaleString()} />
        {log.ttl != null && <Detail label="Cache time (TTL)" value={`${log.ttl}s`} />}
      </View>

      <Heading level={3} style={styles.optionsTitle}>
        Options
      </Heading>
      <View style={styles.grid}>
        <Option
          label="Portable"
          term="portable"
          value={log.portable ? "Yes" : "No"}
          on={log.portable}
        />
        <Option
          label="Pre-rotation"
          term="preRotation"
          value={log.preRotation ? "Yes" : "No"}
          on={log.preRotation}
        />
        <Option
          label="Witnesses"
          term="witness"
          value={log.witnesses ? `${log.witnessThreshold}/${log.witnessCount}` : "None"}
          on={log.witnesses}
        />
        <Option
          label="Watchers"
          term="watcher"
          value={log.watchers ? String(log.watcherCount) : "None"}
          on={log.watchers}
        />
        <Option
          label="Deactivated"
          value={log.deactivated ? "Yes" : "No"}
          on={!log.deactivated}
          alarm={log.deactivated}
        />
      </View>
    </Card>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <View style={styles.detailRow}>
      <Text style={didStyles.label}>{label}</Text>
      <Text style={[styles.detailValue, mono && styles.detailMono]}>{value}</Text>
    </View>
  );
}

/** The value is spelled out ("Yes", "None"), so colour only reinforces it. */
function Option({
  label,
  value,
  on,
  alarm,
  term,
}: {
  label: string;
  value: string;
  on: boolean;
  alarm?: boolean;
  /** Explained with a "?" when set. */
  term?: GlossaryKey;
}) {
  return (
    <View style={styles.option}>
      <Text style={[styles.optionValue, alarm ? styles.alarm : on ? styles.on : styles.off]}>
        {value}
      </Text>
      {term ? (
        <Term term={term} label={label} style={styles.label} />
      ) : (
        <Text style={styles.label}>{label}</Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  grid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.lg,
  },
  item: {
    minWidth: 120,
  },
  value: {
    fontSize: 24,
    fontFamily: fonts.bold,
    color: colors.accentHover,
  },
  small: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textPrimary,
  },
  label: {
    fontSize: 11,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 1,
    marginTop: 2,
  },
  details: {
    gap: spacing.sm,
  },
  detailRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  detailValue: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textPrimary,
  },
  detailMono: {
    fontFamily: fonts.mono,
  },
  optionsTitle: {
    marginTop: spacing.lg,
  },
  option: {
    minWidth: 90,
  },
  optionValue: {
    fontSize: 16,
    fontFamily: fonts.bold,
  },
  on: {
    color: colors.success,
  },
  off: {
    color: colors.textTertiary,
  },
  alarm: {
    color: colors.error,
  },
});
