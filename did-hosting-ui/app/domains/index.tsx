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
import { confirm, notify } from "../../lib/feedback";
import { domainNameError } from "../../lib/validation";
import { errorMessage } from "../../lib/errors";
import { useTrustTaskQuery } from "../../lib/query";
import { ErrorWithRetry } from "../../components/QueryState";
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
  const [retrying, setRetrying] = useState(false);
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

  const nameError = newName === "" ? null : domainNameError(newName);
  const [createError, setCreateError] = useState<string | null>(null);

  const handleCreate = useCallback(async () => {
    if (creating) return;
    const name = newName;
    if (domainNameError(name)) return; // shown inline
    setCreating(true);
    setCreateError(null);
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
      notify(
        "success",
        `${name} created`,
        makeDefault
          ? "It is now the default domain. Assign it to a hosting server on the Servers page so its DIDs resolve."
          : "Assign it to a hosting server on the Servers page so its DIDs resolve.",
      );
    } catch (e: unknown) {
      setCreateError(errorMessage(e));
    } finally {
      setCreating(false);
    }
  }, [api, creating, newName, newLabel, makeDefault, refresh]);

  const handleSetDefault = useCallback(
    async (entry: DomainEntry) => {
      if (entry.status === "disabled") {
        notify("info", "Domain is disabled", "Re-enable the domain before making it the default.");
        return;
      }
      setBusy(entry.name);
      try {
        await api.setDefaultDomain(entry.name);
        await refresh();
        notify("success", "Default domain changed", `${entry.name} is now the default.`);
      } catch (e: unknown) {
        notify("error", "Could not set the default", errorMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handleDisable = useCallback(
    async (entry: DomainEntry) => {
      const grace = graceSeconds && graceSeconds > 0 ? formatDuration(graceSeconds) : null;
      const body =
        `DIDs on ${entry.name} stop resolving immediately. The domain and every DID ` +
        `hosted on it will be permanently removed ` +
        (grace ? `in ${grace}` : "after the configured grace period") +
        ` unless you re-enable it before then.`;
      const ok = await confirm({
        title: `Disable ${entry.name}?`,
        body,
        confirmLabel: "Disable domain",
      });
      if (!ok) return;
      setBusy(entry.name);
      try {
        await api.disableDomain(entry.name);
        await refresh();
        notify(
          "success",
          `${entry.name} disabled`,
          "Re-enable it before the grace period ends to keep its DIDs.",
        );
      } catch (e: unknown) {
        notify("error", "Could not disable the domain", errorMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh, graceSeconds],
  );

  const handleEnable = useCallback(
    async (entry: DomainEntry) => {
      setBusy(entry.name);
      try {
        await api.enableDomain(entry.name);
        await refresh();
        notify(
          "success",
          `${entry.name} enabled`,
          "Its DIDs resolve again and the scheduled removal is cancelled.",
        );
      } catch (e: unknown) {
        notify("error", "Could not enable the domain", errorMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handleDelete = useCallback(
    async (entry: DomainEntry) => {
      const ok = await confirm({
        title: `Delete ${entry.name} now?`,
        body:
          `This skips the rest of the grace period and removes the domain from the control ` +
          `plane immediately. DIDs already copied to hosting servers are not removed there — ` +
          `use “Purge & delete” for that. This cannot be undone.`,
        confirmLabel: "Delete domain",
        typeToConfirm: entry.name,
      });
      if (!ok) return;
      setBusy(entry.name);
      try {
        await api.deleteDomain(entry.name);
        await refresh();
        notify("success", `${entry.name} deleted`);
      } catch (e: unknown) {
        notify("error", "Could not delete the domain", errorMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handlePurgeAndDelete = useCallback(
    async (entry: DomainEntry) => {
      const ok = await confirm({
        title: `Purge & delete ${entry.name}?`,
        body:
          `Every DID hosted on ${entry.name} is permanently deleted from every hosting ` +
          `server that serves it, and the domain is removed from the control plane. The ` +
          `servers are told straight away and carry it out on their own; this page does ` +
          `not wait for each one to finish. This cannot be undone.`,
        confirmLabel: "Purge & delete",
        typeToConfirm: entry.name,
      });
      if (!ok) return;
      setBusy(entry.name);
      try {
        await api.deleteDomain(entry.name, { purgeServers: true });
        await refresh();
        notify(
          "success",
          `${entry.name} deleted`,
          "Hosting servers have been told to purge its DIDs.",
        );
      } catch (e: unknown) {
        notify("error", "Could not purge the domain", errorMessage(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handleRename = useCallback(
    async (entry: DomainEntry, label: string) => {
      setBusy(entry.name);
      try {
        await api.updateDomainLabel(entry.name, label);
        await refresh();
        notify("success", "Label saved", entry.name);
        return true;
      } catch (e: unknown) {
        notify("error", "Could not save the label", errorMessage(e));
        return false;
      } finally {
        setBusy(null);
      }
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
            hint="The host name exactly as DIDs will use it: lowercase, internationalised names in punycode (xn--…). An optional :port or /path-prefix is allowed."
            error={nameError ?? createError}
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
              disabled={!newName || !!nameError}
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

      {error && !loaded ? (
        <ErrorWithRetry
          error={error}
          what="domains"
          retrying={retrying}
          onRetry={() => {
            setRetrying(true);
            void refresh().finally(() => setRetrying(false));
          }}
        />
      ) : error ? (
        <Text role="alert" style={styles.errorText}>
          {error}
        </Text>
      ) : null}

      {error && !loaded ? null : !loaded ? (
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
              onRename={(label) => handleRename(item, label)}
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
  onRename,
}: {
  entry: DomainEntry;
  isDefault: boolean;
  busy: boolean;
  onSetDefault: () => void;
  onDisable: () => void;
  onEnable: () => void;
  onDelete: () => void;
  onPurgeAndDelete: () => void;
  /** Save a new label; resolves `true` when it was saved. */
  onRename: (label: string) => Promise<boolean>;
}) {
  const disabled = entry.status === "disabled";
  const [editingLabel, setEditingLabel] = useState<string | null>(null);
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
          {editingLabel !== null ? (
            <View style={styles.labelEdit}>
              <Field
                label={`Label for ${entry.name}`}
                value={editingLabel}
                onChangeText={setEditingLabel}
                onSubmit={() =>
                  void onRename(editingLabel.trim()).then((ok) => ok && setEditingLabel(null))
                }
                placeholder="Acme Production"
                inputStyle={styles.input}
                style={styles.labelField}
              />
              <Button
                label="Save"
                size="sm"
                busy={busy}
                onPress={() =>
                  void onRename(editingLabel.trim()).then((ok) => ok && setEditingLabel(null))
                }
              />
              <Button
                label="Cancel"
                size="sm"
                variant="secondary"
                onPress={() => setEditingLabel(null)}
              />
            </View>
          ) : (
            !!entry.label && <Text style={styles.cardLabel}>{entry.label}</Text>
          )}
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
        {editingLabel === null && (
          <Button
            label={entry.label ? "Edit label" : "Add label"}
            accessibilityLabel={`Edit the label of ${entry.name}`}
            variant="secondary"
            onPress={() => setEditingLabel(entry.label ?? "")}
          />
        )}
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
  labelEdit: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "flex-end",
    gap: spacing.sm,
    marginTop: spacing.xs,
  },
  labelField: {
    flex: 1,
    minWidth: 200,
    marginBottom: 0,
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
