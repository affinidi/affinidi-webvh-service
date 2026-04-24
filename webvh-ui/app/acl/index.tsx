import { useEffect, useState, useCallback, memo } from "react";
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
import * as Clipboard from "expo-clipboard";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import {
  formatBytes,
  parseMbToBytes,
  bytesToMb,
  parseOptionalInt,
} from "../../lib/format";
import { showAlert, showConfirm } from "../../lib/alert";
import type {
  AclEntry,
  CreateInviteResponse,
  DidRecord,
  InviteListItem,
} from "../../lib/api";

interface EditState {
  did: string;
  role: "admin" | "owner" | "service";
  label: string;
  maxTotalSize: string;
  maxDidCount: string;
}

const formatDate = (ts: number) =>
  new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

const keyExtractor = (item: AclEntry) => item.did;

const AclEntryRow = memo(function AclEntryRow({
  item,
  editing,
  saving,
  onStartEdit,
  onCancelEdit,
  onSave,
  onDelete,
  onChangeRole,
  onChangeLabel,
  onChangeMaxTotalSize,
  onChangeMaxDidCount,
}: {
  item: AclEntry;
  editing: EditState | null;
  saving: boolean;
  onStartEdit: (entry: AclEntry) => void;
  onCancelEdit: () => void;
  onSave: (did: string) => void;
  onDelete: (did: string) => void;
  onChangeRole: (v: "admin" | "owner" | "service") => void;
  onChangeLabel: (v: string) => void;
  onChangeMaxTotalSize: (v: string) => void;
  onChangeMaxDidCount: (v: string) => void;
}) {
  const isEditing = editing?.did === item.did;

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
              item.role === "service" && styles.serviceBadge,
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
            <View style={styles.roleRow}>
              {(["owner", "admin", "service"] as const).map((r) => (
                <Pressable
                  key={r}
                  style={[
                    styles.roleButton,
                    editing.role === r && styles.roleActive,
                  ]}
                  onPress={() => onChangeRole(r)}
                >
                  <Text
                    style={[
                      styles.roleText,
                      editing.role === r && styles.roleTextActive,
                    ]}
                  >
                    {r.charAt(0).toUpperCase() + r.slice(1)}
                  </Text>
                </Pressable>
              ))}
            </View>
            <TextInput
              style={styles.editInput}
              placeholder="Label"
              placeholderTextColor={colors.textTertiary}
              value={editing.label}
              onChangeText={onChangeLabel}
            />
            <View style={styles.editRow}>
              <View style={styles.editFieldHalf}>
                <Text style={styles.editFieldLabel}>Max size (MB)</Text>
                <TextInput
                  style={styles.editInput}
                  placeholder="Default"
                  placeholderTextColor={colors.textTertiary}
                  value={editing.maxTotalSize}
                  onChangeText={onChangeMaxTotalSize}
                  keyboardType="numeric"
                />
              </View>
              <View style={styles.editFieldHalf}>
                <Text style={styles.editFieldLabel}>Max DIDs</Text>
                <TextInput
                  style={styles.editInput}
                  placeholder="Default"
                  placeholderTextColor={colors.textTertiary}
                  value={editing.maxDidCount}
                  onChangeText={onChangeMaxDidCount}
                  keyboardType="numeric"
                />
              </View>
            </View>
            <View style={styles.editActions}>
              <Pressable
                style={[styles.saveButton, saving && styles.disabled]}
                onPress={() => onSave(item.did)}
                disabled={saving}
              >
                <Text style={styles.saveText}>
                  {saving ? "Saving..." : "Save"}
                </Text>
              </Pressable>
              <Pressable style={styles.cancelButton} onPress={onCancelEdit}>
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
            onPress={() => onStartEdit(item)}
          >
            <Text style={styles.editText}>Edit</Text>
          </Pressable>
          <Pressable
            style={styles.deleteButton}
            onPress={() => onDelete(item.did)}
          >
            <Text style={styles.deleteText}>Remove</Text>
          </Pressable>
        </View>
      )}
    </View>
  );
});

export default function AclManagement() {
  const api = useApi();
  const { isAuthenticated } = useAuth();

  const [entries, setEntries] = useState<AclEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New entry form
  const [newDid, setNewDid] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "owner" | "service">("owner");
  const [newLabel, setNewLabel] = useState("");
  const [newMaxTotalSize, setNewMaxTotalSize] = useState("");
  const [newMaxDidCount, setNewMaxDidCount] = useState("");
  const [creating, setCreating] = useState(false);

  // Invite form
  const [inviteDid, setInviteDid] = useState("");
  const [inviteRole, setInviteRole] =
    useState<"admin" | "owner" | "service">("owner");
  const [inviting, setInviting] = useState(false);
  const [invite, setInvite] = useState<CreateInviteResponse | null>(null);
  const [inviteCopied, setInviteCopied] = useState(false);

  // Pending invites (from server)
  const [pendingInvites, setPendingInvites] = useState<InviteListItem[]>([]);
  const [editingInvite, setEditingInvite] = useState<
    { token: string; role: "admin" | "owner" | "service" } | null
  >(null);
  const [invitesBusyToken, setInvitesBusyToken] = useState<string | null>(null);
  const [inviteCopiedToken, setInviteCopiedToken] = useState<string | null>(null);

  // Inline edit state
  const [editing, setEditing] = useState<EditState | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    // Fetch entries + pending invites in parallel. Invite failures are
    // non-fatal — the admin can still see the ACL list if invites are
    // broken for any reason.
    Promise.all([
      api.listAcl(),
      api.listInvites().catch(() => ({ invites: [] as InviteListItem[] })),
    ])
      .then(([aclData, inviteData]) => {
        setEntries(aclData.entries);
        setPendingInvites(inviteData.invites);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleInvite = async () => {
    if (!inviteDid.trim()) return;
    setInviting(true);
    try {
      const resp = await api.createInvite(inviteDid.trim(), inviteRole);
      setInvite(resp);
      setInviteCopied(false);
      // Pull in the newly-created invite for the pending list too.
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create invite";
      showAlert("Error", msg);
    } finally {
      setInviting(false);
    }
  };

  const handleCopyPendingInvite = useCallback(
    async (item: InviteListItem) => {
      await Clipboard.setStringAsync(item.enrollment_url);
      setInviteCopiedToken(item.token);
      setTimeout(
        () =>
          setInviteCopiedToken((prev) => (prev === item.token ? null : prev)),
        2000,
      );
    },
    [],
  );

  const handleRevokeInvite = useCallback(
    (token: string) => {
      showConfirm("Revoke invite", "Revoke this enrollment invite?", async () => {
        setInvitesBusyToken(token);
        try {
          await api.revokeInvite(token);
          refresh();
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : "Failed to revoke";
          showAlert("Error", msg);
        } finally {
          setInvitesBusyToken((prev) => (prev === token ? null : prev));
        }
      });
    },
    [api, refresh],
  );

  const startEditInviteRole = useCallback(
    (item: InviteListItem) =>
      setEditingInvite({ token: item.token, role: item.role }),
    [],
  );

  const cancelEditInviteRole = useCallback(() => setEditingInvite(null), []);

  const handleSaveInviteRole = useCallback(async () => {
    if (!editingInvite) return;
    setInvitesBusyToken(editingInvite.token);
    try {
      await api.updateInvite(editingInvite.token, { role: editingInvite.role });
      setEditingInvite(null);
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to update invite";
      showAlert("Error", msg);
    } finally {
      setInvitesBusyToken((prev) =>
        prev === editingInvite.token ? null : prev,
      );
    }
  }, [api, editingInvite, refresh]);

  const handleCopyInvite = async () => {
    if (!invite) return;
    await Clipboard.setStringAsync(invite.enrollment_url);
    setInviteCopied(true);
    setTimeout(() => setInviteCopied(false), 2000);
  };

  const handleClearInvite = () => {
    setInvite(null);
    setInviteDid("");
  };

  const handleCreate = async () => {
    if (!newDid.trim()) return;
    setCreating(true);
    try {
      await api.createAcl(newDid.trim(), newRole, {
        label: newLabel.trim() || undefined,
        maxTotalSize: parseMbToBytes(newMaxTotalSize) ?? undefined,
        maxDidCount: parseOptionalInt(newMaxDidCount) ?? undefined,
      });
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
          refresh();
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : "Failed to delete";
          showAlert("Error", msg);
        }
      };

      // Fetch DIDs owned by this account, then prompt accordingly
      api
        .listDids(did)
        .then((dids) => {
          if (dids.length === 0) {
            showConfirm(
              "Remove Access",
              `Remove access for ${did}?`,
              () => doDelete(false, []),
            );
          } else {
            showConfirm(
              "Delete DIDs",
              `This account owns ${dids.length} DID(s). Delete them too?`,
              () => doDelete(true, dids),
              () => {
                // User declined deleting DIDs — confirm removing access only
                showConfirm(
                  "Remove Access Only",
                  `Remove access for ${did}? (${dids.length} DID(s) will be kept)`,
                  () => doDelete(false, []),
                );
              },
            );
          }
        })
        .catch((e) => {
          // Can't fetch DIDs — fall back to simple confirmation
          const msg = e instanceof Error ? e.message : "";
          showConfirm(
            "Remove Access",
            `Remove access for ${did}?${msg ? `\n(Could not check owned DIDs: ${msg})` : ""}`,
            () => doDelete(false, []),
          );
        });
    },
    [api, refresh],
  );

  const startEditing = useCallback((entry: AclEntry) => {
    setEditing({
      did: entry.did,
      role: entry.role,
      label: entry.label ?? "",
      maxTotalSize:
        entry.max_total_size != null ? bytesToMb(entry.max_total_size) : "",
      maxDidCount:
        entry.max_did_count != null ? entry.max_did_count.toString() : "",
    });
  }, []);

  const cancelEditing = useCallback(() => {
    setEditing(null);
  }, []);

  const onChangeRole = useCallback(
    (v: "admin" | "owner" | "service") =>
      setEditing((prev) => (prev ? { ...prev, role: v } : prev)),
    [],
  );
  const onChangeLabel = useCallback(
    (v: string) => setEditing((prev) => (prev ? { ...prev, label: v } : prev)),
    [],
  );
  const onChangeMaxTotalSize = useCallback(
    (v: string) =>
      setEditing((prev) => (prev ? { ...prev, maxTotalSize: v } : prev)),
    [],
  );
  const onChangeMaxDidCount = useCallback(
    (v: string) =>
      setEditing((prev) => (prev ? { ...prev, maxDidCount: v } : prev)),
    [],
  );

  const handleSave = useCallback(
    async (did: string) => {
      if (!editing) return;
      setSaving(true);
      try {
        await api.updateAcl(did, {
          role: editing.role,
          label: editing.label.trim() || null,
          maxTotalSize: parseMbToBytes(editing.maxTotalSize),
          maxDidCount: parseOptionalInt(editing.maxDidCount),
        });
        setEditing(null);
        refresh();
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Failed to update";
        showAlert("Error", msg);
      } finally {
        setSaving(false);
      }
    },
    [api, editing, refresh],
  );

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

  const renderEntry = ({ item }: { item: AclEntry }) => (
    <AclEntryRow
      item={item}
      editing={editing}
      saving={saving}
      onStartEdit={startEditing}
      onCancelEdit={cancelEditing}
      onSave={handleSave}
      onDelete={handleDelete}
      onChangeRole={onChangeRole}
      onChangeLabel={onChangeLabel}
      onChangeMaxTotalSize={onChangeMaxTotalSize}
      onChangeMaxDidCount={onChangeMaxDidCount}
    />
  );

  const formatExpiry = (ts: number) => {
    const now = Math.floor(Date.now() / 1000);
    const mins = Math.max(0, Math.round((ts - now) / 60));
    if (mins < 60) return `${mins} min`;
    const hrs = Math.floor(mins / 60);
    const rem = mins % 60;
    return rem === 0 ? `${hrs}h` : `${hrs}h ${rem}m`;
  };

  const header = (
    <View>
      <Text style={styles.title}>Access Control</Text>

      {/* Invite by link */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Invite by Link</Text>
        <Text style={styles.inviteHelp}>
          Generate an enrollment link. The invitee opens it in a browser,
          registers a passkey, and is added to the ACL with the selected role.
        </Text>
        {invite ? (
          <View>
            <Text style={styles.editFieldLabel}>Enrollment URL</Text>
            <View style={styles.inviteUrlBlock}>
              <Text style={styles.inviteUrlText} selectable numberOfLines={2}>
                {invite.enrollment_url}
              </Text>
            </View>
            <Text style={styles.inviteExpiry}>
              Expires in {formatExpiry(invite.expires_at)}
            </Text>
            <View style={styles.editActions}>
              <Pressable style={styles.saveButton} onPress={handleCopyInvite}>
                <Text style={styles.saveText}>
                  {inviteCopied ? "Copied" : "Copy Link"}
                </Text>
              </Pressable>
              <Pressable
                style={styles.cancelButton}
                onPress={handleClearInvite}
              >
                <Text style={styles.cancelText}>New Invite</Text>
              </Pressable>
            </View>
          </View>
        ) : (
          <View>
            <TextInput
              style={styles.input}
              placeholder="did:web:example.com"
              placeholderTextColor={colors.textTertiary}
              value={inviteDid}
              onChangeText={setInviteDid}
              autoCapitalize="none"
              autoCorrect={false}
            />
            <View style={styles.roleRow}>
              {(["owner", "admin", "service"] as const).map((r) => (
                <Pressable
                  key={r}
                  style={[
                    styles.roleButton,
                    inviteRole === r && styles.roleActive,
                  ]}
                  onPress={() => setInviteRole(r)}
                >
                  <Text
                    style={[
                      styles.roleText,
                      inviteRole === r && styles.roleTextActive,
                    ]}
                  >
                    {r.charAt(0).toUpperCase() + r.slice(1)}
                  </Text>
                </Pressable>
              ))}
            </View>
            <Pressable
              style={[
                styles.buttonPrimary,
                (!inviteDid.trim() || inviting) && styles.disabled,
              ]}
              onPress={handleInvite}
              disabled={!inviteDid.trim() || inviting}
            >
              <Text style={styles.buttonPrimaryText}>
                {inviting ? "Generating..." : "Generate Invite"}
              </Text>
            </Pressable>
          </View>
        )}
      </View>

      {/* Pending invites — only shown when there are any */}
      {pendingInvites.length > 0 && (
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>
            Pending Invites ({pendingInvites.length})
          </Text>
          {pendingInvites.map((inv) => {
            const isEditing = editingInvite?.token === inv.token;
            const busy = invitesBusyToken === inv.token;
            return (
              <View key={inv.token} style={styles.pendingInviteRow}>
                <View style={styles.pendingInviteInfo}>
                  <Text style={styles.entryDid} numberOfLines={1}>
                    {inv.did}
                  </Text>
                  <View style={styles.entryMeta}>
                    <View
                      style={[
                        styles.roleBadge,
                        inv.role === "admin" && styles.adminBadge,
                        inv.role === "service" && styles.serviceBadge,
                      ]}
                    >
                      <Text style={styles.roleBadgeText}>{inv.role}</Text>
                    </View>
                    <Text style={styles.entryDate}>
                      {inv.expired
                        ? "expired"
                        : `expires in ${formatExpiry(inv.expires_at)}`}
                    </Text>
                  </View>
                  {isEditing && (
                    <View style={styles.editFields}>
                      <View style={styles.roleRow}>
                        {(["owner", "admin", "service"] as const).map((r) => (
                          <Pressable
                            key={r}
                            style={[
                              styles.roleButton,
                              editingInvite.role === r && styles.roleActive,
                            ]}
                            onPress={() =>
                              setEditingInvite({
                                token: inv.token,
                                role: r,
                              })
                            }
                          >
                            <Text
                              style={[
                                styles.roleText,
                                editingInvite.role === r &&
                                  styles.roleTextActive,
                              ]}
                            >
                              {r.charAt(0).toUpperCase() + r.slice(1)}
                            </Text>
                          </Pressable>
                        ))}
                      </View>
                      <View style={styles.editActions}>
                        <Pressable
                          style={[styles.saveButton, busy && styles.disabled]}
                          onPress={handleSaveInviteRole}
                          disabled={busy}
                        >
                          <Text style={styles.saveText}>
                            {busy ? "Saving..." : "Save role"}
                          </Text>
                        </Pressable>
                        <Pressable
                          style={styles.cancelButton}
                          onPress={cancelEditInviteRole}
                        >
                          <Text style={styles.cancelText}>Cancel</Text>
                        </Pressable>
                      </View>
                    </View>
                  )}
                </View>
                {!isEditing && (
                  <View style={styles.entryActions}>
                    <Pressable
                      style={styles.editButton}
                      onPress={() => handleCopyPendingInvite(inv)}
                    >
                      <Text style={styles.editText}>
                        {inviteCopiedToken === inv.token ? "Copied" : "Copy"}
                      </Text>
                    </Pressable>
                    <Pressable
                      style={styles.editButton}
                      onPress={() => startEditInviteRole(inv)}
                    >
                      <Text style={styles.editText}>Role</Text>
                    </Pressable>
                    <Pressable
                      style={[styles.deleteButton, busy && styles.disabled]}
                      onPress={() => handleRevokeInvite(inv.token)}
                      disabled={busy}
                    >
                      <Text style={styles.deleteText}>Revoke</Text>
                    </Pressable>
                  </View>
                )}
              </View>
            );
          })}
        </View>
      )}

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
          {(["owner", "admin", "service"] as const).map((r) => (
            <Pressable
              key={r}
              style={[
                styles.roleButton,
                newRole === r && styles.roleActive,
              ]}
              onPress={() => setNewRole(r)}
            >
              <Text
                style={[
                  styles.roleText,
                  newRole === r && styles.roleTextActive,
                ]}
              >
                {r.charAt(0).toUpperCase() + r.slice(1)}
              </Text>
            </Pressable>
          ))}
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
        loading ? (
          <ActivityIndicator
            color={colors.accent}
            size="large"
            style={{ marginTop: spacing.xl }}
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
  serviceBadge: {
    backgroundColor: "rgba(168, 85, 247, 0.15)",
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
  inviteHelp: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 19,
    marginBottom: spacing.md,
  },
  pendingInviteRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: spacing.md,
    paddingVertical: spacing.sm,
    borderTopWidth: 1,
    borderTopColor: colors.border,
  },
  pendingInviteInfo: {
    flex: 1,
    minWidth: 0,
  },
  inviteUrlBlock: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.md,
    marginTop: 4,
    marginBottom: spacing.sm,
  },
  inviteUrlText: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.teal,
  },
  inviteExpiry: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginBottom: spacing.sm,
  },
});
