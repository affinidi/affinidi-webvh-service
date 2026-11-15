import type { ReactNode } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";

import { colors, fonts, spacing } from "../lib/theme";
import { useAuth } from "./AuthProvider";

export interface RequireAuthProps {
  /** What the signed-out reader is told: "Please log in to {purpose}." */
  purpose: string;
  children: ReactNode;
}

/**
 * Render `children` only for a signed-in session.
 *
 * While the saved session is still being looked for, a spinner — so a reload
 * does not flash "Please log in" before the session is restored. Signed out,
 * one line saying what signing in would show.
 */
export function RequireAuth({ purpose, children }: RequireAuthProps) {
  const { isAuthenticated, restored } = useAuth();
  if (isAuthenticated) return <>{children}</>;
  return (
    <View style={styles.container}>
      {restored ? (
        <Text style={styles.hint}>Please log in to {purpose}.</Text>
      ) : (
        <ActivityIndicator color={colors.accent} size="large" aria-label="Loading" />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: spacing.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgPrimary,
  },
  hint: {
    fontSize: 15,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
});
