import { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
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
import type { AclEntry } from "../../lib/api";

export default function AclManagement() {
  const api = useApi();
  const { isAuthenticated } = useAuth();

  const [entries, setEntries] = useState<AclEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New entry form
  const [newDid, setNewDid] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "owner">("owner");
  const [newLabel, setNewLabel] = useState("");
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    api
      .listAcl()
      .then((data) => {
        setEntries(data.entries);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleCreate = async () => {
    if (!newDid.trim()) return;
    setCreating(true);
    try {
      await api.createAcl(
        newDid.trim(),
        newRole,
        newLabel.trim() || undefined,
      );
      setNewDid("");
      setNewLabel("");
      refresh();
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Failed to create ACL entry";
      Alert.alert("Error", msg);
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = (did: string) => {
    Alert.alert("Remove Access", `Remove access for ${did}?`, [
      { text: "Cancel", style: "cancel" },
      {
        text: "Remove",
        style: "destructive",
        onPress: async () => {
          try {
            await api.deleteAcl(did);
            refresh();
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : "Failed to delete";
            Alert.alert("Error", msg);
          }
        },
      },
    ]);
  };

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>
          Please log in to manage access control.
        </Text>
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
    });

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Access Control</Text>

      {/* Add new entry */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Add Entry</Text>
        <TextInput
          style={styles.input}
          placeholder="did:web:example.com"
          placeholderTextColor={colors.textTertiary}
          value={newDid}
          onChangeText={setNewDid}
          autoCapitalize="none"
          autoCorrect={false}
        />
        <View style={styles.roleRow}>
          <Pressable
            style={[
              styles.roleButton,
              newRole === "owner" && styles.roleActive,
            ]}
            onPress={() => setNewRole("owner")}
          >
            <Text
              style={[
                styles.roleText,
                newRole === "owner" && styles.roleTextActive,
              ]}
            >
              Owner
            </Text>
          </Pressable>
          <Pressable
            style={[
              styles.roleButton,
              newRole === "admin" && styles.roleActive,
            ]}
            onPress={() => setNewRole("admin")}
          >
            <Text
              style={[
                styles.roleText,
                newRole === "admin" && styles.roleTextActive,
              ]}
            >
              Admin
            </Text>
          </Pressable>
        </View>
        <TextInput
          style={styles.input}
          placeholder="Label (optional)"
          placeholderTextColor={colors.textTertiary}
          value={newLabel}
          onChangeText={setNewLabel}
        />
        <Pressable
          style={[
            styles.buttonPrimary,
            (!newDid.trim() || creating) && styles.disabled,
          ]}
          onPress={handleCreate}
          disabled={!newDid.trim() || creating}
        >
          <Text style={styles.buttonPrimaryText}>
            {creating ? "Adding..." : "Add Entry"}
          </Text>
        </Pressable>
      </View>

      {error && <Text style={styles.errorText}>{error}</Text>}

      {loading ? (
        <ActivityIndicator
          color={colors.accent}
          size="large"
          style={{ marginTop: spacing.xl }}
        />
      ) : entries.length === 0 ? (
        <Text style={styles.hint}>No ACL entries configured.</Text>
      ) : (
        <FlatList
          data={entries}
          keyExtractor={(item) => item.did}
          contentContainerStyle={{ gap: spacing.sm }}
          renderItem={({ item }) => (
            <View style={styles.entryCard}>
              <View style={styles.entryInfo}>
                <Text style={styles.entryDid} numberOfLines={1}>
                  {item.did}
                </Text>
                <View style={styles.entryMeta}>
                  <View
                    style={[
                      styles.roleBadge,
                      item.role === "admin" && styles.adminBadge,
                    ]}
                  >
                    <Text style={styles.roleBadgeText}>{item.role}</Text>
                  </View>
                  {item.label && (
                    <Text style={styles.entryLabel}>{item.label}</Text>
                  )}
                  <Text style={styles.entryDate}>
                    {formatDate(item.created_at)}
                  </Text>
                </View>
              </View>
              <Pressable
                style={styles.deleteButton}
                onPress={() => handleDelete(item.did)}
              >
                <Text style={styles.deleteText}>Remove</Text>
              </Pressable>
            </View>
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
    marginBottom: spacing.xl,
  },
  sectionTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  input: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.md,
    color: colors.textPrimary,
    fontFamily: fonts.regular,
    fontSize: 14,
    marginBottom: spacing.md,
  },
  roleRow: {
    flexDirection: "row",
    gap: spacing.sm,
    marginBottom: spacing.md,
  },
  roleButton: {
    flex: 1,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    paddingVertical: 10,
    alignItems: "center",
  },
  roleActive: {
    borderColor: colors.accent,
    backgroundColor: "rgba(59, 113, 255, 0.12)",
  },
  roleText: {
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
  },
  roleTextActive: {
    color: colors.accent,
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 12,
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
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginTop: spacing.xl,
    marginBottom: spacing.lg,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    marginBottom: spacing.md,
  },
  entryCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 14,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: spacing.md,
  },
  entryInfo: {
    flex: 1,
    minWidth: 0,
  },
  entryDid: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
    marginBottom: spacing.xs,
  },
  entryMeta: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
  },
  roleBadge: {
    backgroundColor: colors.tealMuted,
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  adminBadge: {
    backgroundColor: "rgba(59, 113, 255, 0.15)",
  },
  roleBadgeText: {
    fontSize: 11,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    textTransform: "uppercase",
  },
  entryLabel: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  entryDate: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  deleteButton: {
    borderColor: colors.error,
    borderWidth: 1,
    borderRadius: radii.sm,
    paddingHorizontal: 12,
    paddingVertical: 6,
  },
  deleteText: {
    color: colors.error,
    fontSize: 12,
    fontFamily: fonts.semibold,
  },
});
