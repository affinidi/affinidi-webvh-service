import { useEffect, useState, type ReactNode } from "react";
import {
  ActivityIndicator,
  StyleSheet,
  Text,
  View,
  type StyleProp,
  type ViewStyle,
} from "react-native";

import { errorMessage } from "../lib/errors";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { formatRelative } from "../lib/time";
import { Button } from "./Button";

/** The slice of a `useTrustTaskQuery` result the views below read. */
export interface QueryLike<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  refreshing?: boolean;
  refetch: () => Promise<void>;
}

/**
 * An error with a Retry button — what a read that failed shows in place of
 * its data, so a failure never looks like an empty result.
 */
export function ErrorWithRetry({
  error,
  what,
  onRetry,
  retrying,
  style,
}: {
  error: unknown;
  /** "the DID list" → "Could not load the DID list." */
  what: string;
  onRetry: () => void;
  retrying?: boolean;
  style?: StyleProp<ViewStyle>;
}) {
  return (
    <View role="alert" style={[styles.errorBox, style]}>
      <Text style={styles.errorTitle}>Could not load {what}.</Text>
      <Text style={styles.errorText}>{errorMessage(error)}</Text>
      <Button
        label="Retry"
        accessibilityLabel={`Retry loading ${what}`}
        variant="secondary"
        size="sm"
        busy={retrying}
        busyLabel="Retrying…"
        onPress={onRetry}
        style={styles.retry}
      />
    </View>
  );
}

/**
 * The three states of a read, in one place: a spinner while nothing has
 * loaded, an error with Retry when it failed with nothing to show, and the
 * data otherwise. An error over data already shown is left to
 * `StaleMarker`, so a failed refresh does not blank the screen.
 */
export function QueryView<T>({
  query,
  what,
  children,
  style,
}: {
  query: QueryLike<T>;
  what: string;
  children: (data: T) => ReactNode;
  style?: StyleProp<ViewStyle>;
}) {
  const [retrying, setRetrying] = useState(false);
  if (query.data !== undefined) return <>{children(query.data)}</>;
  if (query.error != null && !retrying) {
    return (
      <ErrorWithRetry
        error={query.error}
        what={what}
        style={style}
        onRetry={() => {
          setRetrying(true);
          void query.refetch().finally(() => setRetrying(false));
        }}
      />
    );
  }
  return (
    <ActivityIndicator
      color={colors.accent}
      size="large"
      aria-label={`Loading ${what}`}
      style={[styles.spinner, style]}
    />
  );
}

/**
 * "Updated 2 minutes ago · refresh failing" for a panel that refreshes on a
 * timer: once data is on screen, a failed poll would otherwise leave stale
 * numbers looking live.
 */
export function StaleMarker({
  updatedAt,
  error,
  onRetry,
}: {
  /** When the data shown was fetched, ms. */
  updatedAt: number | null;
  error: unknown;
  onRetry?: () => void;
}) {
  // Re-render now and then so "2 minutes ago" moves.
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, []);
  if (updatedAt === null) return null;
  const failing = error != null;
  return (
    <View style={styles.staleRow} aria-live="polite">
      <Text style={[styles.staleText, failing && styles.staleFailing]}>
        Last updated {formatRelative(Math.floor(updatedAt / 1000))}
        {failing ? " · refresh failing" : ""}
      </Text>
      {failing && onRetry ? (
        <Button label="Retry" variant="ghost" size="sm" onPress={onRetry} />
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  spinner: {
    marginVertical: spacing.xl,
  },
  errorBox: {
    backgroundColor: colors.errorBg,
    borderColor: colors.error,
    borderWidth: 1,
    borderRadius: radii.md,
    padding: spacing.lg,
    marginVertical: spacing.md,
    alignItems: "flex-start",
  },
  errorTitle: {
    fontFamily: fonts.semibold,
    fontSize: 14,
    color: colors.error,
  },
  errorText: {
    fontFamily: fonts.regular,
    fontSize: 13,
    color: colors.textSecondary,
    marginTop: spacing.xs,
    lineHeight: 18,
  },
  retry: {
    marginTop: spacing.md,
  },
  staleRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
  },
  staleText: {
    fontFamily: fonts.regular,
    fontSize: 12,
    color: colors.textTertiary,
  },
  staleFailing: {
    color: colors.warning,
  },
});
