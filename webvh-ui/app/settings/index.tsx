import { useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  ActivityIndicator,
  ScrollView,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { formatBytes } from "../../lib/format";
import type { ServerConfig } from "../../lib/api";

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value}>{value}</Text>
    </View>
  );
}

function Badge({ enabled }: { enabled: boolean }) {
  return (
    <View style={[styles.badge, enabled ? styles.badgeOn : styles.badgeOff]}>
      <Text style={styles.badgeText}>{enabled ? "Enabled" : "Disabled"}</Text>
    </View>
  );
}

function FeatureRow({ label, enabled }: { label: string; enabled: boolean }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Badge enabled={enabled} />
    </View>
  );
}

export default function SettingsPage() {
  const api = useApi();
  const { isAuthenticated } = useAuth();

  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    api
      .getConfig()
      .then((data) => {
        setConfig(data);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated]);

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>Please log in to view server settings.</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.buttonPrimary}>
            <Text style={styles.buttonPrimaryText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  if (loading) {
    return (
      <View style={styles.containerCenter}>
        <ActivityIndicator color={colors.accent} size="large" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.errorText}>{error}</Text>
      </View>
    );
  }

  if (!config) return null;

  return (
    <ScrollView
      style={styles.scroll}
      contentContainerStyle={styles.container}
    >
      <Text style={styles.title}>Server Settings</Text>

      {/* Server */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Server</Text>
        <Row label="Server DID" value={config.serverDid ?? "Not configured"} />
        <Row label="Public URL" value={config.publicUrl ?? "Not configured"} />
        <Row
          label="Listen Address"
          value={`${config.server.host}:${config.server.port}`}
        />
      </View>

      {/* Features */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Features</Text>
        <FeatureRow label="DIDComm" enabled={config.features.didcomm} />
        <FeatureRow label="REST API" enabled={config.features.restApi} />
      </View>

      {/* Authentication */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Authentication</Text>
        <Row
          label="Access Token Expiry"
          value={formatDuration(config.auth.accessTokenExpiry)}
        />
        <Row
          label="Refresh Token Expiry"
          value={formatDuration(config.auth.refreshTokenExpiry)}
        />
        <Row
          label="Challenge TTL"
          value={formatDuration(config.auth.challengeTtl)}
        />
        <Row
          label="Session Cleanup Interval"
          value={formatDuration(config.auth.sessionCleanupInterval)}
        />
        <Row
          label="Passkey Enrollment TTL"
          value={formatDuration(config.auth.passkeyEnrollmentTtl)}
        />
        <Row
          label="Empty DID Cleanup TTL"
          value={`${config.auth.cleanupTtlMinutes}m`}
        />
      </View>

      {/* Limits */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Limits</Text>
        <Row
          label="Upload Body Limit"
          value={formatBytes(config.limits.uploadBodyLimit)}
        />
        <Row
          label="Max Total Size"
          value={formatBytes(config.limits.defaultMaxTotalSize)}
        />
        <Row
          label="Max DID Count"
          value={config.limits.defaultMaxDidCount.toLocaleString()}
        />
      </View>

      {/* Storage & Logging */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Storage & Logging</Text>
        <Row label="Data Directory" value={config.store.dataDir} />
        <Row label="Log Level" value={config.log.level} />
        <Row label="Log Format" value={config.log.format} />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: {
    flex: 1,
    backgroundColor: colors.bgPrimary,
  },
  container: {
    padding: spacing.xl,
    paddingBottom: spacing.xxxl,
  },
  containerCenter: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    alignItems: "center",
    justifyContent: "center",
  },
  title: {
    fontSize: 22,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    marginBottom: spacing.xl,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    marginBottom: spacing.lg,
  },
  sectionTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  label: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
    flex: 1,
  },
  value: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
    textAlign: "right",
    flex: 1,
  },
  badge: {
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  badgeOn: {
    backgroundColor: colors.tealMuted,
  },
  badgeOff: {
    backgroundColor: colors.errorBg,
  },
  badgeText: {
    fontSize: 11,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    textTransform: "uppercase",
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginBottom: spacing.lg,
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 12,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
  },
});
