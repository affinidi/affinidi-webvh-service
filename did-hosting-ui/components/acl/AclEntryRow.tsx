import { memo } from "react";
import { StyleSheet, Text, View, type TextStyle } from "react-native";
import { Link } from "expo-router";

import type { AclEntry, Role } from "../../lib/api";
import { validateScopeDraft, type ScopeDraft } from "../../lib/acl-scope";
import { formatBytes } from "../../lib/format";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { formatDate } from "../../lib/time";
import { Button } from "../Button";
import { Field } from "../Field";
import { PasskeysCard } from "../PasskeysCard";
import { SegmentedControl } from "../SegmentedControl";
import { quotaError } from "../../lib/validation";
import { ENTRY_ROLES, ROLE_DESCRIPTIONS, RoleBadge } from "./roles";
import { ScopeBadges, ScopeEditor, type AvailableDomain } from "./ScopeEditor";

/** The inline editor's draft of one entry. */
export interface EditState {
  did: string;
  role: Role;
  label: string;
  maxTotalSize: string;
  maxDidCount: string;
  scope: ScopeDraft;
}

export interface AclEntryRowProps {
  item: AclEntry;
  editing: EditState | null;
  saving: boolean;
  availableDomains: AvailableDomain[];
  onStartEdit: (entry: AclEntry) => void;
  onCancelEdit: () => void;
  /** Save the draft over `item`, the entry as it was loaded. */
  onSave: (item: AclEntry) => void;
  onDelete: (did: string) => void;
  onChangeRole: (v: Role) => void;
  onChangeLabel: (v: string) => void;
  onChangeMaxTotalSize: (v: string) => void;
  onChangeMaxDidCount: (v: string) => void;
  onChangeScope: (next: ScopeDraft) => void;
  passkeysExpanded: boolean;
  onTogglePasskeys: (did: string) => void;
}

/** One ACL entry: its read view, or its inline editor. */
export const AclEntryRow = memo(function AclEntryRow({
  item,
  editing,
  saving,
  availableDomains,
  onStartEdit,
  onCancelEdit,
  onSave,
  onDelete,
  onChangeRole,
  onChangeLabel,
  onChangeMaxTotalSize,
  onChangeMaxDidCount,
  onChangeScope,
  passkeysExpanded,
  onTogglePasskeys,
}: AclEntryRowProps) {
  const draft = editing?.did === item.did ? editing : null;
  const scopeError = draft ? validateScopeDraft(draft.scope) : null;
  const sizeError = draft ? quotaError(draft.maxTotalSize) : null;
  const countError = draft ? quotaError(draft.maxDidCount, { integer: true }) : null;
  const invalid = !!(scopeError || sizeError || countError);
  const save = () => {
    if (!saving && !invalid) onSave(item);
  };

  return (
    <View>
      <View style={styles.card}>
        <View style={styles.info}>
          <Link href={`/dids?owner=${encodeURIComponent(item.did)}`}>
            <Text style={styles.did}>{item.did}</Text>
          </Link>
          <View style={styles.meta}>
            <RoleBadge role={item.role} />
            {!draft && item.label && <Text style={styles.label}>{item.label}</Text>}
            <Text style={styles.date}>{formatDate(item.created_at)}</Text>
          </View>

          {draft ? (
            <View style={styles.editFields}>
              <SegmentedControl
                label="Role"
                options={ENTRY_ROLES}
                value={draft.role}
                onChange={onChangeRole}
                style={styles.roleRow}
              />
              <Text style={styles.roleHint}>{ROLE_DESCRIPTIONS[draft.role]}</Text>
              <Field
                label="Label"
                placeholder="Label"
                value={draft.label}
                onChangeText={onChangeLabel}
                onSubmit={save}
              />
              <View style={styles.editRow}>
                <Field
                  label="Max size (MB)"
                  placeholder="Default"
                  value={draft.maxTotalSize}
                  onChangeText={onChangeMaxTotalSize}
                  keyboardType="numeric"
                  error={sizeError}
                  onSubmit={save}
                  style={styles.half}
                />
                <Field
                  label="Max DIDs"
                  placeholder="Default"
                  value={draft.maxDidCount}
                  onChangeText={onChangeMaxDidCount}
                  keyboardType="numeric"
                  error={countError}
                  onSubmit={save}
                  style={styles.half}
                />
              </View>
              <ScopeEditor
                draft={draft.scope}
                availableDomains={availableDomains}
                onChange={onChangeScope}
              />
              {scopeError && (
                <Text role="alert" style={styles.scopeError}>
                  {scopeError}
                </Text>
              )}
              <View style={styles.editActions}>
                <Button
                  label="Save"
                  busyLabel="Saving..."
                  size="sm"
                  busy={saving}
                  disabled={invalid}
                  onPress={save}
                />
                <Button label="Cancel" variant="secondary" size="sm" onPress={onCancelEdit} />
              </View>
            </View>
          ) : (
            <View>
              <View style={styles.quotaRow}>
                <Text style={styles.quotaText}>
                  Max Size:{" "}
                  {item.max_total_size != null ? formatBytes(item.max_total_size) : "Default"}
                </Text>
                <Text style={styles.quotaText}>
                  Max DIDs:{" "}
                  {item.max_did_count != null ? item.max_did_count.toLocaleString() : "Default"}
                </Text>
              </View>
              <View style={styles.scopeReadRow}>
                <Text style={styles.scopeReadLabel}>Domains:</Text>
                <ScopeBadges entry={item} />
              </View>
            </View>
          )}
        </View>

        {!draft && (
          <View style={styles.actions}>
            <Button
              label="Edit"
              accessibilityLabel={`Edit ${item.did}`}
              variant="secondary"
              size="sm"
              onPress={() => onStartEdit(item)}
            />
            <Button
              label={passkeysExpanded ? "Hide passkeys" : "Passkeys"}
              accessibilityLabel={`${passkeysExpanded ? "Hide passkeys" : "Passkeys"} for ${item.did}`}
              variant="secondary"
              size="sm"
              pressed={passkeysExpanded}
              onPress={() => onTogglePasskeys(item.did)}
            />
            <Button
              label="Remove"
              accessibilityLabel={`Remove ${item.did}`}
              variant="danger"
              size="sm"
              onPress={() => onDelete(item.did)}
            />
          </View>
        )}
      </View>
      {passkeysExpanded && (
        <View style={styles.passkeysPanel}>
          <PasskeysCard subject={item.did} purpose="session" title="Sign-in passkeys" />
          <PasskeysCard subject={item.did} purpose="stepUp" title="Step-up passkeys" />
        </View>
      )}
    </View>
  );
});

// Long did:peer values have no whitespace; allow mid-token wrapping so the
// card doesn't blow past its container on web. `wordBreak` is web-only and
// not in React Native's style types.
const breakAll = { wordBreak: "break-all" } as unknown as TextStyle;

const styles = StyleSheet.create({
  card: {
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
  info: {
    flex: 1,
    minWidth: 0,
  },
  did: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
    marginBottom: spacing.xs,
    ...breakAll,
  },
  meta: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
  },
  label: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  date: {
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
  actions: {
    gap: spacing.xs,
  },
  passkeysPanel: {
    marginTop: spacing.md,
    gap: spacing.sm,
  },
  roleHint: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginBottom: spacing.sm,
  },
  editFields: {
    marginTop: spacing.sm,
  },
  roleRow: {
    marginBottom: spacing.md,
  },
  editRow: {
    flexDirection: "row",
    gap: spacing.sm,
  },
  half: {
    flex: 1,
  },
  editActions: {
    flexDirection: "row",
    gap: spacing.sm,
    marginTop: spacing.xs,
  },
  scopeError: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.error,
    marginBottom: spacing.sm,
  },
  scopeReadRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    flexWrap: "wrap",
    marginTop: spacing.xs,
  },
  scopeReadLabel: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
  },
});
