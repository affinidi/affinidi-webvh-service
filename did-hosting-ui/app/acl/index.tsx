import { useCallback, useMemo, useState } from "react";
import { ActivityIndicator, FlatList, StyleSheet, Text, View } from "react-native";

import { useApi } from "../../components/ApiProvider";
import { useDomains } from "../../components/DomainProvider";
import { Heading } from "../../components/Heading";
import { RequireAuth } from "../../components/RequireAuth";
import { AclEntryRow, type EditState } from "../../components/acl/AclEntryRow";
import { AddEntryForm } from "../../components/acl/AddEntryForm";
import { RemoveEntryDialog } from "../../components/acl/RemoveEntryDialog";
import { ErrorWithRetry, StaleMarker } from "../../components/QueryState";
import { useAuth } from "../../components/AuthProvider";
import { InviteCard } from "../../components/acl/InviteCard";
import { ACL_KEY, INVITES_KEY } from "../../components/acl/keys";
import { PendingInvites } from "../../components/acl/PendingInvites";
import {
  aclEntryToDraft,
  draftToScope,
  validateScopeDraft,
  type ScopeDraft,
} from "../../lib/acl-scope";
import type { AclEntry, InviteListItem, Role } from "../../lib/api";
import { errorMessage } from "../../lib/errors";
import { notify } from "../../lib/feedback";
import { bytesToMb, parseMbToBytes, parseOptionalInt } from "../../lib/format";
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

/**
 * Access Control is admin-only: the control plane refuses `acl/list` to
 * anyone else, so an owner is told so plainly rather than shown forms that
 * can only fail.
 */
function AclScreen() {
  const { role } = useAuth();
  if (role !== "admin") {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>
          Access control is managed by administrators. To change who can use this console, ask one
          of them.
        </Text>
      </View>
    );
  }
  return <AclAdmin />;
}

function AclAdmin() {
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
  // Invite failures are non-fatal — the ACL list still shows — but they are
  // said, with a retry, rather than passed off as "no invites".
  const invites = useTrustTaskQuery(INVITES_KEY, () => api.listInvites());
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

  // The entry whose removal dialog is open.
  const [removing, setRemoving] = useState<string | null>(null);
  const handleDelete = useCallback((did: string) => setRemoving(did), []);

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
      if (scopeErr) return; // shown inline; Save is disabled
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
        notify("success", "Entry saved", loaded.did);
      } catch (e: unknown) {
        notify("error", "Could not save the entry", errorMessage(e, "Failed to update"));
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
      {invites.error != null && !invites.data ? (
        <ErrorWithRetry
          error={invites.error}
          what="pending invites"
          onRetry={() => void invites.refetch()}
        />
      ) : (
        <PendingInvites invites={invites.data?.invites ?? NO_INVITES} />
      )}
      <AddEntryForm availableDomains={availableDomains} />
      <View style={styles.listHeader}>
        <Heading level={2} style={styles.listTitle}>
          Entries
        </Heading>
        <StaleMarker
          updatedAt={acl.data ? acl.updatedAt : null}
          error={acl.error}
          onRetry={() => void acl.refetch()}
        />
      </View>
    </View>
  );

  // Render the entire page as a single scrollable FlatList — the Invite
  // and Add Entry cards live inside ListHeaderComponent so they scroll
  // with the entry list rather than taking up static screen real estate
  // above it. Empty / loading states live in ListEmptyComponent.
  return (
    <>
      <FlatList
        style={styles.container}
        contentContainerStyle={styles.scrollContent}
        data={entries}
        keyExtractor={keyExtractor}
        ListHeaderComponent={header}
        renderItem={renderEntry}
        ListEmptyComponent={
          acl.error != null && !acl.data ? (
            <ErrorWithRetry
              error={acl.error}
              what="the access control list"
              onRetry={() => void acl.refetch()}
            />
          ) : acl.loading ? (
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
      {removing && <RemoveEntryDialog did={removing} onClose={() => setRemoving(null)} />}
    </>
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
  containerCenter: {
    flex: 1,
    padding: spacing.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgPrimary,
  },
  listHeader: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    justifyContent: "space-between",
    gap: spacing.sm,
    marginBottom: spacing.sm,
  },
  listTitle: {
    marginBottom: 0,
  },
});
