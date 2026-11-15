import type { ReactNode } from "react";
import { ActivityIndicator, StyleSheet, View } from "react-native";

import { colors, spacing } from "../lib/theme";
import { useAuth } from "./AuthProvider";

export interface RequireAuthProps {
  /** What the page is for — its loading indicator's name. */
  purpose: string;
  children: ReactNode;
}

/**
 * Render `children` only while there is a session — or while one has just
 * expired, so the page and anything typed into it stay put under the
 * "session expired" prompt (`AuthGate`).
 *
 * Signed out, the route guard is already on its way to the sign-in page;
 * until it gets there this shows a spinner, never a "please log in" stub.
 */
export function RequireAuth({ purpose, children }: RequireAuthProps) {
  const { isAuthenticated, sessionExpired } = useAuth();
  if (isAuthenticated || sessionExpired) return <>{children}</>;
  return (
    <View style={styles.container}>
      <ActivityIndicator color={colors.accent} size="large" aria-label={`Loading — ${purpose}`} />
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
});
