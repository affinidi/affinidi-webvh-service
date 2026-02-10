import { useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  ActivityIndicator,
} from "react-native";
import { Link } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { useApi } from "../components/ApiProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { colors, fonts, radii, spacing } from "../lib/theme";
import type { HealthResponse } from "../lib/api";

export default function Dashboard() {
  const { isAuthenticated, logout } = useAuth();
  const api = useApi();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [didCount, setDidCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch((e) => setError(e.message));
  }, [api]);

  useEffect(() => {
    if (!isAuthenticated) return;
    api
      .listDids()
      .then((dids) => setDidCount(dids.length))
      .catch(() => {});
  }, [isAuthenticated, api]);

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
    <View style={styles.container}>
      <AffinidiLogo size={48} />

      <Text style={styles.subtitle}>Decentralized Identity Hosting</Text>

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
          {didCount !== null && (
            <View style={styles.card}>
              <Text style={styles.cardLabel}>Total DIDs</Text>
              <Text style={styles.cardValueAccent}>{didCount}</Text>
            </View>
          )}
        </View>
      ) : (
        <ActivityIndicator color={colors.accent} size="large" />
      )}

      <View style={styles.nav}>
        <Link href="/dids" asChild>
          <Pressable style={styles.buttonSecondary}>
            <Text style={styles.buttonSecondaryText}>Manage DIDs</Text>
          </Pressable>
        </Link>
        <Link href="/acl" asChild>
          <Pressable style={styles.buttonSecondary}>
            <Text style={styles.buttonSecondaryText}>Access Control</Text>
          </Pressable>
        </Link>
        <Pressable style={styles.logoutButton} onPress={logout}>
          <Text style={styles.logoutButtonText}>Logout</Text>
        </Pressable>
      </View>
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
  subtitle: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginTop: spacing.md,
    marginBottom: spacing.xxl,
    letterSpacing: 0.5,
  },
  statusRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.md,
    justifyContent: "center",
    marginBottom: spacing.lg,
    width: "100%",
    maxWidth: 500,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    minWidth: 140,
    flex: 1,
  },
  errorCard: {
    backgroundColor: colors.errorBg,
    borderColor: colors.error,
    width: "100%",
    maxWidth: 500,
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
  nav: {
    marginTop: spacing.lg,
    gap: spacing.md,
    width: "100%",
    maxWidth: 500,
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 14,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
  buttonSecondary: {
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 14,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
  },
  buttonSecondaryText: {
    color: colors.textPrimary,
    fontSize: 16,
    fontFamily: fonts.medium,
  },
  logoutButton: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.error,
    paddingVertical: 14,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
    marginTop: spacing.md,
  },
  logoutButtonText: {
    color: colors.error,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
});
