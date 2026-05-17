/**
 * Admin Domains view — list + create + enable / disable / set-default.
 *
 * The non-admin path simply hides this page from the nav, but
 * defence-in-depth: a non-admin who navigates here directly sees a
 * redirect-to-login message rather than a partially-populated UI.
 *
 * Layout:
 * - Header: title + "+ New domain" toggle.
 * - Inline create form (collapsed by default).
 * - Domain cards stacked vertically, each surfacing:
 *   * canonical name + label
 *   * status badge (Active / Disabled)
 *   * Default chip when it's the system default
 *   * created-at timestamp
 *   * inline actions: Set as default · Disable / Enable
 */

import { useCallback, useState } from "react";
import {
  ActivityIndicator,
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { useDomains } from "../../components/DomainProvider";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { showAlert, showConfirm } from "../../lib/alert";
import type { DomainEntry } from "../../lib/api";

export default function DomainsScreen() {
  const { isAuthenticated, role } = useAuth();
  const api = useApi();
  const { domains, loaded, error, defaultDomain, refresh } = useDomains();

  const [showForm, setShowForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [makeDefault, setMakeDefault] = useState(false);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const handleCreate = useCallback(async () => {
    const name = newName.trim().toLowerCase();
    if (!name) {
      showAlert("Domain name required", "Enter a host like 'example.com'.");
      return;
    }
    setCreating(true);
    try {
      await api.createDomain({
        name,
        label: newLabel.trim() || undefined,
        setAsDefault: makeDefault,
      });
      await refresh();
      setShowForm(false);
      setNewName("");
      setNewLabel("");
      setMakeDefault(false);
    } catch (e: unknown) {
      showAlert("Create failed", e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  }, [api, newName, newLabel, makeDefault, refresh]);

  const handleSetDefault = useCallback(
    async (entry: DomainEntry) => {
      if (entry.status === "disabled") {
        showAlert(
          "Domain is disabled",
          "Re-enable the domain before promoting it to default.",
        );
        return;
      }
      setBusy(entry.name);
      try {
        await api.setDefaultDomain(entry.name);
        await refresh();
      } catch (e: unknown) {
        showAlert(
          "Set default failed",
          e instanceof Error ? e.message : String(e),
        );
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handleDisable = useCallback(
    (entry: DomainEntry) => {
      showConfirm(
        `Disable ${entry.name}?`,
        "Resolves on this domain will return 503 with a maintenance body. " +
          "Hosted DIDs are preserved — re-enable to restore traffic.",
        async () => {
          setBusy(entry.name);
          try {
            await api.disableDomain(entry.name);
            await refresh();
          } catch (e: unknown) {
            showAlert(
              "Disable failed",
              e instanceof Error ? e.message : String(e),
            );
          } finally {
            setBusy(null);
          }
        },
      );
    },
    [api, refresh],
  );

  const handleEnable = useCallback(
    async (entry: DomainEntry) => {
      setBusy(entry.name);
      try {
        await api.enableDomain(entry.name);
        await refresh();
      } catch (e: unknown) {
        showAlert("Enable failed", e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>Please log in to manage domains.</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.buttonPrimary}>
            <Text style={styles.buttonPrimaryText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  if (role !== "admin") {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>
          Domain administration is restricted to Admin accounts.
        </Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View style={{ flex: 1 }}>
          <Text style={styles.title}>Domains</Text>
          <Text style={styles.subtitle}>
            Hosting domains this control plane serves. Set one as the system
            default — it's used when an Owner registers a DID without a
            `domain` field.
          </Text>
        </View>
        <Pressable
          accessibilityRole="button"
          style={styles.buttonPrimary}
          onPress={() => setShowForm((s) => !s)}
        >
          <Text style={styles.buttonPrimaryText}>
            {showForm ? "Cancel" : "+ New domain"}
          </Text>
        </Pressable>
      </View>

      {showForm && (
        <View style={styles.formCard}>
          <Text style={styles.formLabel}>Canonical name</Text>
          <TextInput
            value={newName}
            onChangeText={setNewName}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="example.com"
            placeholderTextColor={colors.textTertiary}
            style={styles.input}
          />
          <Text style={styles.formHint}>
            Lowercased + IDNA-normalised by the daemon. Public hosts only.
          </Text>

          <Text style={styles.formLabel}>Friendly label (optional)</Text>
          <TextInput
            value={newLabel}
            onChangeText={setNewLabel}
            placeholder="Acme Production"
            placeholderTextColor={colors.textTertiary}
            style={styles.input}
          />

          <Pressable
            accessibilityRole="checkbox"
            accessibilityState={{ checked: makeDefault }}
            onPress={() => setMakeDefault((v) => !v)}
            style={styles.checkboxRow}
          >
            <View
              style={[
                styles.checkbox,
                makeDefault && styles.checkboxChecked,
              ]}
            >
              {makeDefault && <Text style={styles.checkboxTick}>✓</Text>}
            </View>
            <Text style={styles.checkboxLabel}>
              Set as system default after creating
            </Text>
          </Pressable>

          <View style={styles.formActions}>
            <Pressable
              accessibilityRole="button"
              onPress={handleCreate}
              disabled={creating}
              style={[
                styles.buttonPrimary,
                creating && styles.buttonDisabled,
              ]}
            >
              <Text style={styles.buttonPrimaryText}>
                {creating ? "Creating…" : "Create domain"}
              </Text>
            </Pressable>
            <Pressable
              accessibilityRole="button"
              onPress={() => setShowForm(false)}
              disabled={creating}
              style={styles.buttonSecondary}
            >
              <Text style={styles.buttonSecondaryText}>Cancel</Text>
            </Pressable>
          </View>
        </View>
      )}

      {error && <Text style={styles.errorText}>{error}</Text>}

      {!loaded ? (
        <ActivityIndicator color={colors.accent} size="large" style={styles.spinner} />
      ) : domains.length === 0 ? (
        <Text style={styles.hint}>
          No domains yet. Create one above to start hosting DIDs.
        </Text>
      ) : (
        <FlatList
          data={domains}
          keyExtractor={(item) => item.name}
          contentContainerStyle={{ gap: spacing.md }}
          renderItem={({ item }) => (
            <DomainCard
              entry={item}
              isDefault={defaultDomain === item.name}
              busy={busy === item.name}
              onSetDefault={() => handleSetDefault(item)}
              onDisable={() => handleDisable(item)}
              onEnable={() => handleEnable(item)}
            />
          )}
        />
      )}
    </View>
  );
}

function DomainCard({
  entry,
  isDefault,
  busy,
  onSetDefault,
  onDisable,
  onEnable,
}: {
  entry: DomainEntry;
  isDefault: boolean;
  busy: boolean;
  onSetDefault: () => void;
  onDisable: () => void;
  onEnable: () => void;
}) {
  const disabled = entry.status === "disabled";
  return (
    <View
      style={[
        styles.card,
        isDefault && styles.cardDefault,
        disabled && styles.cardDisabled,
      ]}
    >
      <View style={styles.cardHeader}>
        <View style={{ flex: 1 }}>
          <View style={styles.nameRow}>
            <Text style={styles.cardName}>{entry.name}</Text>
            {isDefault && (
              <View style={styles.defaultBadge}>
                <Text style={styles.defaultBadgeText}>Default</Text>
              </View>
            )}
            <View
              style={[
                styles.statusBadge,
                disabled ? styles.statusBadgeDisabled : styles.statusBadgeActive,
              ]}
            >
              <Text
                style={[
                  styles.statusBadgeText,
                  disabled
                    ? styles.statusBadgeTextDisabled
                    : styles.statusBadgeTextActive,
                ]}
              >
                {disabled ? "Disabled" : "Active"}
              </Text>
            </View>
          </View>
          {!!entry.label && <Text style={styles.cardLabel}>{entry.label}</Text>}
          <Text style={styles.cardMeta}>
            {entry.scheme} · created{" "}
            {new Date(entry.createdAt * 1000).toLocaleDateString(undefined, {
              year: "numeric",
              month: "short",
              day: "numeric",
            })}
            {entry.wellKnownEnabled ? " · /.well-known enabled" : ""}
          </Text>
        </View>
      </View>

      <View style={styles.cardActions}>
        {!isDefault && !disabled && (
          <Pressable
            accessibilityRole="button"
            onPress={onSetDefault}
            disabled={busy}
            style={[styles.buttonSecondary, busy && styles.buttonDisabled]}
          >
            <Text style={styles.buttonSecondaryText}>
              {busy ? "…" : "Set as default"}
            </Text>
          </Pressable>
        )}
        {disabled ? (
          <Pressable
            accessibilityRole="button"
            onPress={onEnable}
            disabled={busy}
            style={[styles.buttonSecondary, busy && styles.buttonDisabled]}
          >
            <Text style={styles.buttonSecondaryText}>
              {busy ? "…" : "Enable"}
            </Text>
          </Pressable>
        ) : (
          <Pressable
            accessibilityRole="button"
            onPress={onDisable}
            disabled={busy || isDefault}
            style={[
              styles.buttonDanger,
              (busy || isDefault) && styles.buttonDisabled,
            ]}
          >
            <Text style={styles.buttonDangerText}>
              {busy ? "…" : isDefault ? "Disable (re-point default first)" : "Disable"}
            </Text>
          </Pressable>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    gap: spacing.lg,
  },
  containerCenter: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    alignItems: "center",
    justifyContent: "center",
  },
  spinner: { marginTop: spacing.xxl },
  header: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: spacing.md,
    flexWrap: "wrap",
  },
  title: {
    fontSize: 24,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
  },
  subtitle: {
    marginTop: 4,
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    maxWidth: 640,
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginTop: spacing.xxl,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    marginBottom: spacing.md,
  },
  formCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    gap: spacing.sm,
  },
  formLabel: {
    fontFamily: fonts.semibold,
    fontSize: 12,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.6,
    marginTop: spacing.sm,
  },
  formHint: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  input: {
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 10,
    paddingHorizontal: spacing.md,
    color: colors.textPrimary,
    fontFamily: fonts.mono,
    fontSize: 14,
  },
  checkboxRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    marginTop: spacing.sm,
  },
  checkbox: {
    width: 18,
    height: 18,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: colors.border,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgTertiary,
  },
  checkboxChecked: {
    borderColor: colors.accent,
    backgroundColor: colors.accent,
  },
  checkboxTick: {
    color: colors.textOnAccent,
    fontFamily: fonts.bold,
    fontSize: 12,
    lineHeight: 14,
  },
  checkboxLabel: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textPrimary,
  },
  formActions: {
    flexDirection: "row",
    gap: spacing.md,
    marginTop: spacing.md,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    gap: spacing.md,
  },
  cardDefault: {
    borderLeftWidth: 4,
    borderLeftColor: colors.teal,
  },
  cardDisabled: {
    opacity: 0.7,
  },
  cardHeader: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: spacing.md,
  },
  nameRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    flexWrap: "wrap",
  },
  cardName: {
    fontFamily: fonts.semibold,
    fontSize: 16,
    color: colors.textPrimary,
  },
  cardLabel: {
    marginTop: 4,
    fontFamily: fonts.medium,
    fontSize: 13,
    color: colors.textSecondary,
  },
  cardMeta: {
    marginTop: 6,
    fontFamily: fonts.regular,
    fontSize: 12,
    color: colors.textTertiary,
  },
  defaultBadge: {
    backgroundColor: colors.tealMuted,
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
    borderRadius: radii.sm,
  },
  defaultBadgeText: {
    fontFamily: fonts.semibold,
    fontSize: 10,
    color: colors.teal,
    letterSpacing: 0.4,
  },
  statusBadge: {
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
    borderRadius: radii.sm,
  },
  statusBadgeActive: {
    backgroundColor: colors.tealMuted,
  },
  statusBadgeDisabled: {
    backgroundColor: colors.errorBg,
  },
  statusBadgeText: {
    fontFamily: fonts.semibold,
    fontSize: 10,
    letterSpacing: 0.4,
  },
  statusBadgeTextActive: { color: colors.teal },
  statusBadgeTextDisabled: { color: colors.error },
  cardActions: {
    flexDirection: "row",
    gap: spacing.sm,
    flexWrap: "wrap",
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 10,
    paddingHorizontal: spacing.lg,
    alignItems: "center",
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontFamily: fonts.semibold,
    fontSize: 14,
  },
  buttonSecondary: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 10,
    paddingHorizontal: spacing.lg,
    alignItems: "center",
  },
  buttonSecondaryText: {
    color: colors.textSecondary,
    fontFamily: fonts.semibold,
    fontSize: 14,
  },
  buttonDanger: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.error,
    paddingVertical: 10,
    paddingHorizontal: spacing.lg,
    alignItems: "center",
  },
  buttonDangerText: {
    color: colors.error,
    fontFamily: fonts.semibold,
    fontSize: 14,
  },
  buttonDisabled: { opacity: 0.5 },
});
