/**
 * `UsageChart`, loaded on first render rather than with the app.
 *
 * The chart is the only user of `recharts`, a large share of the bundle.
 * Imported statically, it landed in the shared chunk every route loads —
 * the login page included. Behind `import()` the export puts it in a chunk
 * of its own, fetched when a page that shows a chart first renders one.
 */

import { Suspense, lazy } from "react";
import { ActivityIndicator, View } from "react-native";

import { colors, spacing } from "../lib/theme";

const UsageChart = lazy(() => import("./UsageChart").then((m) => ({ default: m.UsageChart })));

export function LazyUsageChart({ mnemonic }: { mnemonic?: string }) {
  return (
    <Suspense
      fallback={
        <View style={{ paddingVertical: spacing.xl }}>
          <ActivityIndicator color={colors.accent} aria-label="Loading chart" />
        </View>
      }
    >
      <UsageChart mnemonic={mnemonic} />
    </Suspense>
  );
}
