import { useCallback, useMemo, useState } from "react";
import { ActivityIndicator, FlatList, StyleSheet, Text, View } from "react-native";

import { useApi } from "../../components/ApiProvider";
import { useDomains } from "../../components/DomainProvider";
import { Heading } from "../../components/Heading";
import { RequireAuth } from "../../components/RequireAuth";
import { AclEntryRow, type EditState } from "../../components/acl/AclEntryRow";
import { AddEntryForm } from "../../components/acl/AddEntryForm";
import { InviteCard } from "../../components/acl/InviteCard";
import { ACL_KEY, INVITES_KEY } from "../../components/acl/keys";
import { PendingInvites } from "../../components/acl/PendingInvites";
import {
  aclEntryToDraft,
  draftToScope,
  validateScopeDraft,
  type ScopeDraft,
} from "../../lib/acl-scope";
import { showAlert, showConfirm } from "../../lib/alert";
import type { AclEntry, DidRecord, InviteListItem, Role } from "../../lib/api";
import { errorMessage } from "../../lib/errors";
import { bytesToMb, parseMbToBytes, parseOptionalInt } from "../../lib/format";
import { plural } from "../../lib/plural";
import { invalidateQueries, useTrustTaskQuery } from "../../lib/query";
import { colors, fonts, spacing } from "../../lib/theme";

const keyExtractor = (item: AclEntry) => item.did;
const NO_INVITES: InviteListItem[] = [];

export default function AclManagement() {
  return (
    <RequireAuth purpose="manage access control">
      <AclScreen />
    </RequireAuth>
  );
}

function AclScreen() {
  const api = useApi();
  const { domains: domainCatalog } = useDomains();

  // Trimmed view of `domainCatalog` for ScopeEditor — name + disabled flag.
  // Disabled domains stay visible so admins can still see what's selected,
  // but the button is greyed out.
  const availableDomains = useMemo(
    () => domainCatalog.map((d) => ({ name: d.name, disabled: d.status === "disabled" })),
    [domainCatalog],
  );

  const acl = useTrustTaskQuery(ACL_KEY, () => api.listAcl());
  // Invite failures are non-fatal — the admin can still see the ACL list if
  // invites are broken for any reason.
  const invites = useTrustTaskQuery(INVITES_KEY, () =>
    api.listInvites().catch(() => ({ invites: NO_INVITES })),
  );
  const entries = acl.data?.entries ?? [];

  // Inline edit state
  const [editing, setEditing] = useState<EditState | null>(null);
  const [saving, setSaving] = useState(false);

  // Which entries' passkey panel is expanded — a lost passkey is recovered
  // here: an administrator revokes the missing credential, then re-invites.
  const [expandedPasskeys, setExpandedPasskeys] = useState<Set<string>>(new Set());
  const togglePasskeys = useCallback((did: string) => {
    setExpandedPasskeys((prev) => {
      const next = new Set(prev);
      if (next.has(did)) next.delete(did);
      else next.add(did);
      return next;
    });
  }, []);

  const handleDelete = useCallback(
    (did: string) => {
      const doDelete = async (deleteDids: boolean, dids: DidRecord[]) => {
        try {
          if (deleteDids && dids.length > 0) {
            for (const d of dids) {
              await api.deleteDid(d.mnemonic);
            }
          }
          await api.deleteAcl(did);
          await invalidateQueries(ACL_KEY, ["dids"]);
        } catch (e: unknown) {
          showAlert("Error", errorMessage(e, "Failed to delete"));
        }
      };

      // Fetch DIDs owned by this account, then prompt accordingly
      api
        .listDids(did)
        .then((dids) => {
          if (dids.length === 0) {
            showConfirm("Remove Access", `Remove access for ${did}?`, () => doDelete(false, []));
          } else {
            const owned = plural(dids.length, "DID", "DIDs");
            showConfirm(
              "Delete DIDs",
              `This account owns ${owned}. Delete them too?`,
              () => doDelete(true, dids),
              () => {
                // User declined deleting DIDs — confirm removing access only
                showConfirm(
                  "Remove Access Only",
                  `Remove access for ${did}? (${owned} will be kept)`,
                  () => doDelete(false, []),
                );
              },
            );
          }
        })
        .catch((e: unknown) => {
          // Can't fetch DIDs — fall back to simple confirmation
          const msg = errorMessage(e, "");
          showConfirm(
            "Remove Access",
            `Remove access for ${did}?${msg ? `\n(Could not check owned DIDs: ${msg})` : ""}`,
            () => doDelete(false, []),
          );
        });
    },
    [api],
  );

  const startEditing = useCallback((entry: AclEntry) => {
    setEditing({
      did: entry.did,
      role: entry.role,
      label: entry.label ?? "",
      maxTotalSize: entry.max_total_size != null ? bytesToMb(entry.max_total_size) : "",
      maxDidCount: entry.max_did_count != null ? entry.max_did_count.toString() : "",
      scope: aclEntryToDraft(entry),
    });
  }, []);

  const cancelEditing = useCallback(() => setEditing(null), []);

  const onChangeRole = useCallback(
    (v: Role) => setEditing((prev) => (prev ? { ...prev, role: v } : prev)),
    [],
  );
  const onChangeLabel = useCallback(
    (v: string) => setEditing((prev) => (prev ? { ...prev, label: v } : prev)),
    [],
  );
  const onChangeMaxTotalSize = useCallback(
    (v: string) => setEditing((prev) => (prev ? { ...prev, maxTotalSize: v } : prev)),
    [],
  );
  const onChangeMaxDidCount = useCallback(
    (v: string) => setEditing((prev) => (prev ? { ...prev, maxDidCount: v } : prev)),
    [],
  );
  const onChangeScope = useCallback(
    (next: ScopeDraft) => setEditing((prev) => (prev ? { ...prev, scope: next } : prev)),
    [],
  );

  const handleSave = useCallback(
    async (loaded: AclEntry) => {
      if (!editing) return;
      const scopeErr = validateScopeDraft(editing.scope);
      if (scopeErr) {
        showAlert("Invalid scope", scopeErr);
        return;
      }
      setSaving(true);
      try {
        // Diffed against the entry as loaded: an unchanged save sends nothing.
        await api.updateAcl(
          loaded.did,
          {
            role: editing.role,
            label: editing.label.trim() || null,
            maxTotalSize: parseMbToBytes(editing.maxTotalSize),
            maxDidCount: parseOptionalInt(editing.maxDidCount),
            domains: draftToScope(editing.scope),
          },
          loaded,
        );
        setEditing(null);
        await invalidateQueries(ACL_KEY);
      } catch (e: unknown) {
        showAlert("Error", errorMessage(e, "Failed to update"));
        // A multi-step update may have half-applied; show the entry as it is.
        void invalidateQueries(ACL_KEY);
      } finally {
        setSaving(false);
      }
    },
    [api, editing],
  );

  const renderEntry = ({ item }: { item: AclEntry }) => (
    <AclEntryRow
      item={item}
      editing={editing}
      saving={saving}
      availableDomains={availableDomains}
      onStartEdit={startEditing}
      onCancelEdit={cancelEditing}
      onSave={handleSave}
      onDelete={handleDelete}
      onChangeRole={onChangeRole}
      onChangeLabel={onChangeLabel}
      onChangeMaxTotalSize={onChangeMaxTotalSize}
      onChangeMaxDidCount={onChangeMaxDidCount}
      onChangeScope={onChangeScope}
      passkeysExpanded={expandedPasskeys.has(item.did)}
      onTogglePasskeys={togglePasskeys}
    />
  );

  const header = (
    <View>
      <Heading level={1}>Access Control</Heading>
      <InviteCard />
      <PendingInvites invites={invites.data?.invites ?? NO_INVITES} />
      <AddEntryForm availableDomains={availableDomains} />
      {acl.error != null && (
        <Text role="alert" style={styles.errorText}>
          {errorMessage(acl.error, "Failed to load the access control list")}
        </Text>
      )}
    </View>
  );

  // Render the entire page as a single scrollable FlatList — the Invite
  // and Add Entry cards live inside ListHeaderComponent so they scroll
  // with the entry list rather than taking up static screen real estate
  // above it. Empty / loading states live in ListEmptyComponent.
  return (
    <FlatList
      style={styles.container}
      contentContainerStyle={styles.scrollContent}
      data={entries}
      keyExtractor={keyExtractor}
      ListHeaderComponent={header}
      renderItem={renderEntry}
      ListEmptyComponent={
        acl.loading ? (
          <ActivityIndicator
            color={colors.accent}
            size="large"
            style={styles.spinner}
            aria-label="Loading"
          />
        ) : (
          <Text style={styles.hint}>No ACL entries configured.</Text>
        )
      }
      ItemSeparatorComponent={EntrySeparator}
    />
  );
}

const EntrySeparator = () => <View style={styles.entrySeparator} />;

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.bgPrimary,
  },
  scrollContent: {
    padding: spacing.xl,
    // Room at the bottom so the last ACL entry isn't flush with the
    // viewport edge on short lists.
    paddingBottom: spacing.xxl,
  },
  entrySeparator: {
    height: spacing.sm,
  },
  spinner: {
    marginTop: spacing.xl,
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
});
