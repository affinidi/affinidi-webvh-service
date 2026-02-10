import { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  FlatList,
  ActivityIndicator,
  Alert,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import type { DidRecord } from "../../lib/api";

export default function DidList() {
  const api = useApi();
  const { isAuthenticated } = useAuth();
  const [dids, setDids] = useState<DidRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    api
      .listDids()
      .then((data) => {
        setDids(data);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await api.createDid();
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create DID";
      Alert.alert("Error", msg);
    } finally {
      setCreating(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>Please log in to manage DIDs.</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.buttonPrimary}>
            <Text style={styles.buttonPrimaryText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  const formatDate = (ts: number) =>
    new Date(ts * 1000).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Your DIDs</Text>
        <Pressable
          style={[styles.buttonPrimary, creating && styles.disabled]}
          onPress={handleCreate}
          disabled={creating}
        >
          <Text style={styles.buttonPrimaryText}>
            {creating ? "Creating..." : "Request New DID"}
          </Text>
        </Pressable>
      </View>

      {error && <Text style={styles.errorText}>{error}</Text>}

      {loading ? (
        <ActivityIndicator
          color={colors.accent}
          size="large"
          style={{ marginTop: spacing.xxl }}
        />
      ) : dids.length === 0 ? (
        <Text style={styles.hint}>
          No DIDs yet. Create one to get started.
        </Text>
      ) : (
        <FlatList
          data={dids}
          keyExtractor={(item) => item.mnemonic}
          contentContainerStyle={{ gap: spacing.md }}
          renderItem={({ item }) => (
            <Link href={`/dids/${item.mnemonic}`} asChild>
              <Pressable style={styles.card}>
                <Text style={styles.mnemonic}>{item.mnemonic}</Text>
                <View style={styles.meta}>
                  <Text style={styles.metaText}>
                    Versions: {item.versionCount}
                  </Text>
                  <Text style={styles.metaText}>
                    Updated: {formatDate(item.updatedAt)}
                  </Text>
                </View>
              </Pressable>
            </Link>
          )}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
  },
  containerCenter: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    alignItems: "center",
    justifyContent: "center",
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: spacing.xl,
    flexWrap: "wrap",
    gap: spacing.md,
  },
  title: {
    fontSize: 22,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
  },
  mnemonic: {
    fontSize: 16,
    fontFamily: fonts.mono,
    fontWeight: "600",
    color: colors.accent,
    marginBottom: spacing.sm,
  },
  meta: {
    flexDirection: "row",
    gap: spacing.lg,
  },
  metaText: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginTop: spacing.xxl,
    marginBottom: spacing.lg,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    marginBottom: spacing.md,
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 12,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
  },
  disabled: {
    opacity: 0.5,
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
});
