import { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  Pressable,
  FlatList,
  ActivityIndicator,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { formatBytes } from "../../lib/format";
import { showAlert, showConfirm } from "../../lib/alert";
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
  const [newMaxTotalSize, setNewMaxTotalSize] = useState("");
  const [newMaxDidCount, setNewMaxDidCount] = useState("");
  const [creating, setCreating] = useState(false);

  // Inline edit state
  const [editingDid, setEditingDid] = useState<string | null>(null);
  const [editLabel, setEditLabel] = useState("");
  const [editMaxTotalSize, setEditMaxTotalSize] = useState("");
  const [editMaxDidCount, setEditMaxDidCount] = useState("");
  const [saving, setSaving] = useState(false);

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
      const maxSize = newMaxTotalSize.trim()
        ? Math.round(parseFloat(newMaxTotalSize) * 1024 * 1024)
        : undefined;
      const maxDids = newMaxDidCount.trim()
        ? parseInt(newMaxDidCount, 10)
        : undefined;
      await api.createAcl(
        newDid.trim(),
        newRole,
        newLabel.trim() || undefined,
        maxSize,
        maxDids,
      );
      setNewDid("");
      setNewLabel("");
      setNewMaxTotalSize("");
      setNewMaxDidCount("");
      refresh();
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Failed to create ACL entry";
      showAlert("Error", msg);
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = (did: string) => {
    showConfirm("Remove Access", `Remove access for ${did}?`, async () => {
      try {
        await api.deleteAcl(did);
        refresh();
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Failed to delete";
        showAlert("Error", msg);
      }
    });
  };

  const startEditing = (entry: AclEntry) => {
    setEditingDid(entry.did);
    setEditLabel(entry.label ?? "");
    setEditMaxTotalSize(
      entry.max_total_size != null
        ? (entry.max_total_size / (1024 * 1024)).toString()
        : "",
    );
    setEditMaxDidCount(
      entry.max_did_count != null ? entry.max_did_count.toString() : "",
    );
  };

  const cancelEditing = () => {
    setEditingDid(null);
  };

  const handleSave = async (did: string) => {
    setSaving(true);
    try {
      const label = editLabel.trim() || null;
      const maxSize = editMaxTotalSize.trim()
        ? Math.round(parseFloat(editMaxTotalSize) * 1024 * 1024)
        : null;
      const maxDids = editMaxDidCount.trim()
        ? parseInt(editMaxDidCount, 10)
        : null;
      await api.updateAcl(did, {
        label,
        max_total_size: maxSize,
        max_did_count: maxDids,
      });
      setEditingDid(null);
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to update";
      showAlert("Error", msg);
    } finally {
      setSaving(false);
    }
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

  const renderEntry = ({ item }: { item: AclEntry }) => {
    const isEditing = editingDid === item.did;

    return (
      <View style={styles.entryCard}>
        <View style={styles.entryInfo}>
          <Link href={`/dids?owner=${encodeURIComponent(item.did)}`}>
            <Text style={styles.entryDid} numberOfLines={1}>
              {item.did}
            </Text>
          </Link>
          <View style={styles.entryMeta}>
            <View
              style={[
                styles.roleBadge,
                item.role === "admin" && styles.adminBadge,
              ]}
            >
              <Text style={styles.roleBadgeText}>{item.role}</Text>
            </View>
            {!isEditing && item.label && (
              <Text style={styles.entryLabel}>{item.label}</Text>
            )}
            <Text style={styles.entryDate}>
              {formatDate(item.created_at)}
            </Text>
          </View>

          {isEditing ? (
            <View style={styles.editFields}>
              <TextInput
                style={styles.editInput}
                placeholder="Label"
                placeholderTextColor={colors.textTertiary}
                value={editLabel}
                onChangeText={setEditLabel}
              />
              <View style={styles.editRow}>
                <View style={styles.editFieldHalf}>
                  <Text style={styles.editFieldLabel}>Max size (MB)</Text>
                  <TextInput
                    style={styles.editInput}
                    placeholder="Default"
                    placeholderTextColor={colors.textTertiary}
                    value={editMaxTotalSize}
                    onChangeText={setEditMaxTotalSize}
                    keyboardType="numeric"
                  />
                </View>
                <View style={styles.editFieldHalf}>
                  <Text style={styles.editFieldLabel}>Max DIDs</Text>
                  <TextInput
                    style={styles.editInput}
                    placeholder="Default"
                    placeholderTextColor={colors.textTertiary}
                    value={editMaxDidCount}
                    onChangeText={setEditMaxDidCount}
                    keyboardType="numeric"
                  />
                </View>
              </View>
              <View style={styles.editActions}>
                <Pressable
                  style={[styles.saveButton, saving && styles.disabled]}
                  onPress={() => handleSave(item.did)}
                  disabled={saving}
                >
                  <Text style={styles.saveText}>
                    {saving ? "Saving..." : "Save"}
                  </Text>
                </Pressable>
                <Pressable style={styles.cancelButton} onPress={cancelEditing}>
                  <Text style={styles.cancelText}>Cancel</Text>
                </Pressable>
              </View>
            </View>
          ) : (
            <View style={styles.quotaRow}>
              <Text style={styles.quotaText}>
                Max Size:{" "}
                {item.max_total_size != null
                  ? formatBytes(item.max_total_size)
                  : "Default"}
              </Text>
              <Text style={styles.quotaText}>
                Max DIDs:{" "}
                {item.max_did_count != null
                  ? item.max_did_count.toLocaleString()
                  : "Default"}
              </Text>
            </View>
          )}
        </View>

        {!isEditing && (
          <View style={styles.entryActions}>
            <Pressable
              style={styles.editButton}
              onPress={() => startEditing(item)}
            >
              <Text style={styles.editText}>Edit</Text>
            </Pressable>
            <Pressable
              style={styles.deleteButton}
              onPress={() => handleDelete(item.did)}
            >
              <Text style={styles.deleteText}>Remove</Text>
            </Pressable>
          </View>
        )}
      </View>
    );
  };

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
        <View style={styles.quotaInputRow}>
          <View style={styles.quotaInputHalf}>
            <TextInput
              style={styles.input}
              placeholder="Max total size (MB)"
              placeholderTextColor={colors.textTertiary}
              value={newMaxTotalSize}
              onChangeText={setNewMaxTotalSize}
              keyboardType="numeric"
            />
          </View>
          <View style={styles.quotaInputHalf}>
            <TextInput
              style={styles.input}
              placeholder="Max DID count"
              placeholderTextColor={colors.textTertiary}
              value={newMaxDidCount}
              onChangeText={setNewMaxDidCount}
              keyboardType="numeric"
            />
          </View>
        </View>
        <Text style={styles.quotaHint}>
          Leave blank to use server default
        </Text>
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
          renderItem={renderEntry}
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
  quotaInputRow: {
    flexDirection: "row",
    gap: spacing.sm,
  },
  quotaInputHalf: {
    flex: 1,
  },
  quotaHint: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginBottom: spacing.md,
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
    alignItems: "flex-start",
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
  quotaRow: {
    flexDirection: "row",
    gap: spacing.md,
    marginTop: spacing.xs,
  },
  quotaText: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  entryActions: {
    gap: spacing.xs,
  },
  editButton: {
    borderColor: colors.accent,
    borderWidth: 1,
    borderRadius: radii.sm,
    paddingHorizontal: 12,
    paddingVertical: 6,
    alignItems: "center",
  },
  editText: {
    color: colors.accent,
    fontSize: 12,
    fontFamily: fonts.semibold,
  },
  deleteButton: {
    borderColor: colors.error,
    borderWidth: 1,
    borderRadius: radii.sm,
    paddingHorizontal: 12,
    paddingVertical: 6,
    alignItems: "center",
  },
  deleteText: {
    color: colors.error,
    fontSize: 12,
    fontFamily: fonts.semibold,
  },
  editFields: {
    marginTop: spacing.sm,
  },
  editInput: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.sm,
    color: colors.textPrimary,
    fontFamily: fonts.regular,
    fontSize: 13,
    marginBottom: spacing.sm,
  },
  editRow: {
    flexDirection: "row",
    gap: spacing.sm,
  },
  editFieldHalf: {
    flex: 1,
  },
  editFieldLabel: {
    fontSize: 11,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
    marginBottom: 4,
  },
  editActions: {
    flexDirection: "row",
    gap: spacing.sm,
    marginTop: spacing.xs,
  },
  saveButton: {
    backgroundColor: colors.accent,
    borderRadius: radii.sm,
    paddingHorizontal: 14,
    paddingVertical: 6,
    alignItems: "center",
  },
  saveText: {
    color: colors.textOnAccent,
    fontSize: 12,
    fontFamily: fonts.semibold,
  },
  cancelButton: {
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    paddingHorizontal: 14,
    paddingVertical: 6,
    alignItems: "center",
  },
  cancelText: {
    color: colors.textSecondary,
    fontSize: 12,
    fontFamily: fonts.semibold,
  },
});
