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
import { ActivityIndicator, FlatList, Pressable, StyleSheet, Text, View } from "react-native";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { Button } from "../../components/Button";
import { useDomains } from "../../components/DomainProvider";
import { Field } from "../../components/Field";
import { Heading } from "../../components/Heading";
import { RequireAuth } from "../../components/RequireAuth";
import { colors, focusRing, fonts, radii, spacing } from "../../lib/theme";
import { showAlert, showConfirm } from "../../lib/alert";
import { errorMessage } from "../../lib/errors";
import { useTrustTaskQuery } from "../../lib/query";
import { formatDate, formatDuration, formatRelative } from "../../lib/time";
import type { DomainEntry } from "../../lib/api";

export default function DomainsScreen() {
  return (
    <RequireAuth purpose="manage domains">
      <DomainsBody />
    </RequireAuth>
  );
}

function DomainsBody() {
  const { role } = useAuth();
  const api = useApi();
  const { domains, loaded, error, defaultDomain, refresh } = useDomains();
  // Server-info is best-effort: a failure here just means we fall back to
  // generic copy in the disable confirm. The service DID and its public facts
  // are stable for the tab, so one read serves every screen.
  const { data: serverInfo } = useTrustTaskQuery(["server", "info"], () => api.serverInfo(), {
    staleTime: Infinity,
  });
  const graceSeconds = serverInfo?.domainPurgeGraceSeconds ?? null;

  const [showForm, setShowForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [makeDefault, setMakeDefault] = useState(false);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const handleCreate = useCallback(async () => {
    if (creating) return;
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
      showAlert("Create failed", errorMessage(e));
    } finally {
      setCreating(false);
    }
  }, [api, creating, newName, newLabel, makeDefault, refresh]);

  const handleSetDefault = useCallback(
    async (entry: DomainEntry) => {
      if (entry.status === "disabled") {
        showAlert("Domain is disabled", "Re-enable the domain before promoting it to default.");
        return;
      }
      setBusy(entry.name);
      try {
        await api.setDefaultDomain(entry.name);
        await refresh();
      } catch (e: unknown) {
        showAlert("Set default failed", errorMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handleDisable = useCallback(
    (entry: DomainEntry) => {
      const grace = graceSeconds && graceSeconds > 0 ? formatDuration(graceSeconds) : null;
      const body = grace
        ? `Resolves return 503 immediately. The domain and EVERY hosted DID ` +
          `will be permanently removed in ${grace} unless you re-enable ` +
          `before then.`
        : `Resolves return 503 immediately. The domain and EVERY hosted DID ` +
          `will be permanently removed after the configured grace period ` +
          `unless you re-enable before then.`;
      showConfirm(`Disable ${entry.name}?`, body, async () => {
        setBusy(entry.name);
        try {
          await api.disableDomain(entry.name);
          await refresh();
        } catch (e: unknown) {
          showAlert("Disable failed", errorMessage(e));
        } finally {
          setBusy(null);
        }
      });
    },
    [api, refresh, graceSeconds],
  );

  const handleEnable = useCallback(
    async (entry: DomainEntry) => {
      setBusy(entry.name);
      try {
        await api.enableDomain(entry.name);
        await refresh();
      } catch (e: unknown) {
        showAlert("Enable failed", errorMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handleDelete = useCallback(
    (entry: DomainEntry) => {
      showConfirm(
        `Delete ${entry.name} now?`,
        `This bypasses the cooling-off window and removes the domain ` +
          `record immediately. Hosted DIDs (if any) are not removed — ` +
          `purge them per-server first if you want a clean wipe. This ` +
          `cannot be undone.`,
        async () => {
          setBusy(entry.name);
          try {
            await api.deleteDomain(entry.name);
            await refresh();
          } catch (e: unknown) {
            showAlert("Delete failed", errorMessage(e));
          } finally {
            setBusy(null);
          }
        },
      );
    },
    [api, refresh],
  );

  const handlePurgeAndDelete = useCallback(
    (entry: DomainEntry) => {
      showConfirm(
        `Purge & delete ${entry.name}?`,
        `Every server serving this domain will receive a domain.purge ` +
          `message — every DID hosted on the domain across the fleet ` +
          `will be permanently removed. The control-plane domain ` +
          `record is then deleted. Server purges are fire-and-forget ` +
          `over DIDComm; this UI won't wait for acks. Cannot be undone.`,
        async () => {
          setBusy(entry.name);
          try {
            await api.deleteDomain(entry.name, { purgeServers: true });
            await refresh();
          } catch (e: unknown) {
            showAlert("Purge & delete failed", errorMessage(e));
          } finally {
            setBusy(null);
          }
        },
      );
    },
    [api, refresh],
  );

  if (role !== "admin") {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>Domain administration is restricted to Admin accounts.</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View style={{ flex: 1 }}>
          <Heading style={styles.title}>Domains</Heading>
          <Text style={styles.subtitle}>
            Hosting domains this control plane serves. Set one as the system default — it&apos;s
            used when an Owner registers a DID without a `domain` field.
          </Text>
        </View>
        <Button
          label={showForm ? "Cancel" : "+ New domain"}
          expanded={showForm}
          onPress={() => setShowForm((s) => !s)}
        />
      </View>

      {showForm && (
        <View style={styles.formCard}>
          <Field
            label="Canonical name"
            value={newName}
            onChangeText={setNewName}
            onSubmit={handleCreate}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="example.com"
            hint="Lowercased + IDNA-normalised by the daemon. Public hosts only."
            inputStyle={styles.input}
          />

          <Field
            label="Friendly label (optional)"
            value={newLabel}
            onChangeText={setNewLabel}
            onSubmit={handleCreate}
            placeholder="Acme Production"
            inputStyle={styles.input}
          />

          <Checkbox
            checked={makeDefault}
            label="Set as system default after creating"
            onToggle={() => setMakeDefault((v) => !v)}
          />

          <View style={styles.formActions}>
            <Button
              label="Create domain"
              busy={creating}
              busyLabel="Creating…"
              onPress={handleCreate}
            />
            <Button
              label="Cancel"
              variant="secondary"
              disabled={creating}
              onPress={() => setShowForm(false)}
            />
          </View>
        </View>
      )}

      {error && (
        <Text role="alert" style={styles.errorText}>
          {error}
        </Text>
      )}

      {!loaded ? (
        <ActivityIndicator
          color={colors.accent}
          size="large"
          aria-label="Loading domains"
          style={styles.spinner}
        />
      ) : domains.length === 0 ? (
        <Text style={styles.hint}>No domains yet. Create one above to start hosting DIDs.</Text>
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
              onDelete={() => handleDelete(item)}
              onPurgeAndDelete={() => handlePurgeAndDelete(item)}
            />
          )}
        />
      )}
    </View>
  );
}

/** A labelled checkbox: `role="checkbox"` with its checked state, focusable,
 *  toggled with Space or Enter. */
function Checkbox({
  checked,
  label,
  onToggle,
}: {
  checked: boolean;
  label: string;
  onToggle: () => void;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <Pressable
      role="checkbox"
      aria-checked={checked}
      aria-label={label}
      onPress={onToggle}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      style={StyleSheet.flatten([styles.checkboxRow, focused && focusRing])}
    >
      <View style={[styles.checkbox, checked && styles.checkboxChecked]}>
        {checked && <Text style={styles.checkboxTick}>✓</Text>}
      </View>
      <Text style={styles.checkboxLabel}>{label}</Text>
    </Pressable>
  );
}

function DomainCard({
  entry,
  isDefault,
  busy,
  onSetDefault,
  onDisable,
  onEnable,
  onDelete,
  onPurgeAndDelete,
}: {
  entry: DomainEntry;
  isDefault: boolean;
  busy: boolean;
  onSetDefault: () => void;
  onDisable: () => void;
  onEnable: () => void;
  onDelete: () => void;
  onPurgeAndDelete: () => void;
}) {
  const disabled = entry.status === "disabled";
  return (
    <View
      role="region"
      aria-label={entry.name}
      style={[styles.card, isDefault && styles.cardDefault, disabled && styles.cardDisabled]}
    >
      <View style={styles.cardHeader}>
        <View style={{ flex: 1 }}>
          <View style={styles.nameRow}>
            <Heading level={2} style={styles.cardName}>
              {entry.name}
            </Heading>
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
                  disabled ? styles.statusBadgeTextDisabled : styles.statusBadgeTextActive,
                ]}
              >
                {disabled ? "Disabled" : "Active"}
              </Text>
            </View>
          </View>
          {!!entry.label && <Text style={styles.cardLabel}>{entry.label}</Text>}
          <Text style={styles.cardMeta}>
            {entry.scheme} · created {formatDate(entry.createdAt)}
            {entry.wellKnownEnabled ? " · /.well-known enabled" : ""}
          </Text>
          {disabled && entry.purgeAt ? (
            <Text style={styles.cardWarning}>
              Will be permanently removed {formatRelative(entry.purgeAt)} ·{" "}
              {formatDate(entry.purgeAt, { withTime: true })}. Re-enable to cancel.
            </Text>
          ) : null}
        </View>
      </View>

      <View style={styles.cardActions}>
        {!isDefault && !disabled && (
          <Button
            label="Set as default"
            accessibilityLabel={`Set ${entry.name} as default`}
            variant="secondary"
            busy={busy}
            busyLabel="…"
            onPress={onSetDefault}
          />
        )}
        {disabled ? (
          <>
            <Button
              label="Enable"
              accessibilityLabel={`Enable ${entry.name}`}
              variant="secondary"
              busy={busy}
              busyLabel="…"
              onPress={onEnable}
            />
            <Button
              label="Delete now"
              accessibilityLabel={`Delete ${entry.name} now`}
              variant="danger"
              busy={busy}
              busyLabel="…"
              onPress={onDelete}
            />
            <Button
              label="Purge & delete"
              accessibilityLabel={`Purge and delete ${entry.name}`}
              variant="danger"
              busy={busy}
              busyLabel="…"
              onPress={onPurgeAndDelete}
            />
          </>
        ) : (
          <Button
            label={isDefault ? "Disable (re-point default first)" : "Disable"}
            accessibilityLabel={
              isDefault ? `Disable ${entry.name} (re-point default first)` : `Disable ${entry.name}`
            }
            variant="danger"
            busy={busy}
            busyLabel="…"
            disabled={isDefault}
            onPress={onDisable}
          />
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
    marginBottom: 0,
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
    marginBottom: 0,
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
  cardWarning: {
    marginTop: 6,
    fontFamily: fonts.medium,
    fontSize: 12,
    color: colors.error,
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
});
