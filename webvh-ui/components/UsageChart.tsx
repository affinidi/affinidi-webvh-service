import { useEffect, useState } from "react";
import { View, Text, Pressable, StyleSheet, ActivityIndicator } from "react-native";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useApi } from "./ApiProvider";
import { colors, fonts, radii, spacing } from "../lib/theme";
import type { TimeSeriesPoint, TimeRange } from "../lib/api";

const RANGES: { label: string; value: TimeRange }[] = [
  { label: "1h", value: "1h" },
  { label: "24h", value: "24h" },
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
];

function formatTick(ts: number, range: TimeRange): string {
  const d = new Date(ts * 1000);
  if (range === "1h" || range === "24h") {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function formatTooltipLabel(label: any): string {
  return new Date(Number(label) * 1000).toLocaleString();
}

export function UsageChart({ mnemonic }: { mnemonic?: string }) {
  const api = useApi();
  const [range, setRange] = useState<TimeRange>("24h");
  const [data, setData] = useState<TimeSeriesPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    const fetcher = mnemonic
      ? api.getDidTimeseries(mnemonic, range)
      : api.getServerTimeseries(range);
    fetcher
      .then((points) => {
        setData(points);
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, [api, mnemonic, range]);

  return (
    <View style={styles.card}>
      <View style={styles.header}>
        <Text style={styles.title}>Usage Over Time</Text>
        <View style={styles.rangeRow}>
          {RANGES.map((r) => (
            <Pressable
              key={r.value}
              onPress={() => setRange(r.value)}
              style={[
                styles.rangeButton,
                range === r.value && styles.rangeButtonActive,
              ]}
            >
              <Text
                style={[
                  styles.rangeText,
                  range === r.value && styles.rangeTextActive,
                ]}
              >
                {r.label}
              </Text>
            </Pressable>
          ))}
        </View>
      </View>

      {error ? (
        <Text style={styles.errorText}>{error}</Text>
      ) : loading ? (
        <View style={styles.loadingBox}>
          <ActivityIndicator color={colors.accent} />
        </View>
      ) : (
        <div style={{ width: "100%", height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
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
                tickFormatter={(ts) => formatTick(ts, range)}
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
        </div>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    marginBottom: spacing.lg,
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: spacing.md,
  },
  title: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
  },
  rangeRow: {
    flexDirection: "row",
    gap: spacing.xs,
  },
  rangeButton: {
    paddingVertical: 4,
    paddingHorizontal: spacing.sm,
    borderRadius: radii.sm,
    borderWidth: 1,
    borderColor: colors.border,
  },
  rangeButtonActive: {
    backgroundColor: colors.accent,
    borderColor: colors.accent,
  },
  rangeText: {
    fontSize: 12,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
  },
  rangeTextActive: {
    color: colors.textOnAccent,
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
});
