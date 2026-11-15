import type { ReactNode } from "react";
import { useState } from "react";
import { View, Text, StyleSheet, ActivityIndicator } from "react-native";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  type TooltipPayloadEntry,
} from "recharts";
import { useApi } from "./ApiProvider";
import { Card } from "./Card";
import { useDomains } from "./DomainProvider";
import { SegmentedControl } from "./SegmentedControl";
import { errorMessage } from "../lib/errors";
import { useTrustTaskQuery } from "../lib/query";
import { colors, fonts, radii, spacing } from "../lib/theme";
import type { TimeRange } from "../lib/api";
import { formatRate, pointSeconds, STEP_SECS } from "../lib/usage-rate";

const RANGES: { label: string; value: TimeRange; accessibilityLabel: string }[] = [
  { label: "1h", value: "1h", accessibilityLabel: "Last hour" },
  { label: "24h", value: "24h", accessibilityLabel: "Last 24 hours" },
  { label: "7d", value: "7d", accessibilityLabel: "Last 7 days" },
  { label: "30d", value: "30d", accessibilityLabel: "Last 30 days" },
];

function formatTick(ts: number, range: TimeRange): string {
  const d = new Date(ts * 1000);
  if (range === "1h" || range === "24h") {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function formatTooltipLabel(label: ReactNode): string {
  return new Date(Number(label) * 1000).toLocaleString();
}

export function UsageChart({ mnemonic }: { mnemonic?: string }) {
  const api = useApi();
  // The dashboard variant (no `mnemonic`) follows the global domain
  // switcher. The per-DID variant ignores it — a DID is bound to a
  // single domain and the chart filter would only ever match or hide
  // its own series.
  const { currentDomain } = useDomains();
  const [range, setRange] = useState<TimeRange>("24h");
  const domain = mnemonic ? null : (currentDomain ?? null);

  // The range (and DID or domain) is part of the key, so a quick range switch
  // can never paint the previous range's answer: each range is its own entry,
  // and the chart shows only the one it is on.
  const { data, loading, error } = useTrustTaskQuery(
    ["stats", "timeseries", mnemonic ?? null, domain, range],
    ({ background }) =>
      mnemonic
        ? api.getDidTimeseries(mnemonic, range, { background })
        : api.getServerTimeseries(range, domain ?? undefined, { background }),
  );

  return (
    <Card
      title="Usage Over Time"
      style={styles.card}
      headerRight={
        <SegmentedControl label="Time range" options={RANGES} value={range} onChange={setRange} />
      }
    >
      {error && !data ? (
        <Text role="alert" style={styles.errorText}>
          {errorMessage(error)}
        </Text>
      ) : loading ? (
        <View style={styles.loadingBox}>
          <ActivityIndicator color={colors.accent} aria-label="Loading usage" />
        </View>
      ) : !data || data.length === 0 ? (
        <View style={styles.loadingBox}>
          <Text style={styles.emptyText}>No usage data yet</Text>
        </View>
      ) : (
        <View style={{ width: "100%", height: 260 }}>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="gradResolves" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B71FF" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3B71FF" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradUpdates" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#1FE5CD" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#1FE5CD" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="timestamp"
                tickFormatter={(ts: number) => formatTick(ts, range)}
                stroke={colors.textTertiary}
                fontSize={11}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                allowDecimals={false}
                stroke={colors.textTertiary}
                fontSize={11}
                tickLine={false}
                axisLine={false}
                width={40}
              />
              <Tooltip
                labelFormatter={formatTooltipLabel}
                // Each point carries its own width (hourly for a DID without
                // 5-minute detail); the rate is over the time it covers
                // (`lib/usage-rate`).
                formatter={(value, name, item: TooltipPayloadEntry) => {
                  const point = item?.payload as { timestamp?: unknown; seconds?: unknown };
                  const count = Number(value) || 0;
                  const start = Number(point?.timestamp) || 0;
                  const step = Number(point?.seconds) || STEP_SECS[range];
                  const secs = pointSeconds(start, step, Math.floor(Date.now() / 1000));
                  return [`${count.toLocaleString()} (${formatRate(count, secs)})`, name];
                }}
                contentStyle={{
                  backgroundColor: colors.bgSecondary,
                  border: `1px solid ${colors.border}`,
                  borderRadius: radii.sm,
                  fontSize: 12,
                  color: colors.textPrimary,
                }}
                itemStyle={{ color: colors.textPrimary }}
                labelStyle={{ color: colors.textSecondary, marginBottom: 4 }}
              />
              <Area
                type="monotone"
                dataKey="resolves"
                stroke="#3B71FF"
                fill="url(#gradResolves)"
                strokeWidth={2}
                name="Resolves"
              />
              <Area
                type="monotone"
                dataKey="updates"
                stroke="#1FE5CD"
                fill="url(#gradUpdates)"
                strokeWidth={2}
                name="Updates"
              />
            </AreaChart>
          </ResponsiveContainer>
        </View>
      )}
    </Card>
  );
}

const styles = StyleSheet.create({
  card: {
    marginBottom: spacing.lg,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    fontSize: 14,
  },
  loadingBox: {
    height: 260,
    justifyContent: "center",
    alignItems: "center",
  },
  emptyText: {
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    fontSize: 14,
  },
});
