import { useCallback, useState } from "react";
import { StyleSheet, Text, View } from "react-native";

import type { InviteListItem, Role } from "../../lib/api";
import { confirm, notify } from "../../lib/feedback";
import { errorMessage } from "../../lib/errors";
import { invalidateQueries } from "../../lib/query";
import { colors, fonts, spacing } from "../../lib/theme";
import { formatRelative } from "../../lib/time";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { SegmentedControl } from "../SegmentedControl";
import { INVITES_KEY } from "./keys";
import { INVITE_ROLES, RoleBadge } from "./roles";

/** The invites issued and not yet redeemed. Renders nothing when there are none. */
export function PendingInvites({ invites }: { invites: InviteListItem[] }) {
  const api = useApi();
  const [editing, setEditing] = useState<{ inviteId: string; role: Role } | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const handleRevoke = useCallback(
    async (inviteId: string) => {
      const ok = await confirm({
        title: "Revoke this invite?",
        body: "The enrolment link and claim code stop working. You can send a new invite later.",
        confirmLabel: "Revoke invite",
      });
      if (!ok) return;
      setBusyId(inviteId);
      try {
        await api.revokeInvite(inviteId);
        await invalidateQueries(INVITES_KEY);
        notify("success", "Invite revoked");
      } catch (e: unknown) {
        notify("error", "Could not revoke the invite", errorMessage(e, "Failed to revoke"));
      } finally {
        setBusyId((prev) => (prev === inviteId ? null : prev));
      }
    },
    [api],
  );

  const handleSaveRole = useCallback(async () => {
    if (!editing) return;
    const { inviteId, role } = editing;
    setBusyId(inviteId);
    try {
      await api.updateInvite(inviteId, { role });
      setEditing(null);
      await invalidateQueries(INVITES_KEY);
    } catch (e: unknown) {
      notify("error", "Could not update the invite", errorMessage(e, "Failed to update invite"));
    } finally {
      setBusyId((prev) => (prev === inviteId ? null : prev));
    }
  }, [api, editing]);

  if (invites.length === 0) return null;

  return (
    <Card title={`Pending Invites (${invites.length.toLocaleString()})`} style={styles.card}>
      {invites.map((inv) => {
        const isEditing = editing?.inviteId === inv.inviteId;
        const busy = busyId === inv.inviteId;
        return (
          <View key={inv.inviteId} style={styles.row}>
            <View style={styles.info}>
              <Text style={styles.did} numberOfLines={1}>
                {inv.did}
              </Text>
              <View style={styles.meta}>
                <RoleBadge role={inv.role} text={inv.purpose === "stepUp" ? "step-up" : inv.role} />
                <Text style={styles.date}>
                  {inv.expired ? "expired" : `expires ${formatRelative(inv.expiresAt)}`}
                </Text>
              </View>
              {isEditing && (
                <View style={styles.editFields}>
                  <SegmentedControl
                    label={`Role for ${inv.did}`}
                    options={INVITE_ROLES}
                    value={editing.role === "metricsReader" ? null : editing.role}
                    onChange={(role) => setEditing({ inviteId: inv.inviteId, role })}
                    style={styles.roleRow}
                  />
                  <View style={styles.actions}>
                    <Button
                      label="Save role"
                      busyLabel="Saving..."
                      size="sm"
                      busy={busy}
                      onPress={handleSaveRole}
                    />
                    <Button
                      label="Cancel"
                      variant="secondary"
                      size="sm"
                      onPress={() => setEditing(null)}
                    />
                  </View>
                </View>
              )}
            </View>
            {!isEditing && (
              <View style={styles.rowActions}>
                {inv.purpose === "session" && (
                  <Button
                    label="Role"
                    accessibilityLabel={`Change role for ${inv.did}`}
                    variant="secondary"
                    size="sm"
                    onPress={() => setEditing({ inviteId: inv.inviteId, role: inv.role })}
                  />
                )}
                <Button
                  label="Revoke"
                  accessibilityLabel={`Revoke invite for ${inv.did}`}
                  variant="danger"
                  size="sm"
                  disabled={busy}
                  onPress={() => handleRevoke(inv.inviteId)}
                />
              </View>
            )}
          </View>
        );
      })}
    </Card>
  );
}

const styles = StyleSheet.create({
  card: {
    marginBottom: spacing.xl,
  },
  row: {
    flexDirection: "row",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: spacing.md,
    paddingVertical: spacing.sm,
    borderTopWidth: 1,
    borderTopColor: colors.border,
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
  },
  meta: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
  },
  date: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  editFields: {
    marginTop: spacing.sm,
  },
  roleRow: {
    marginBottom: spacing.md,
  },
  actions: {
    flexDirection: "row",
    gap: spacing.sm,
    marginTop: spacing.xs,
  },
  rowActions: {
    gap: spacing.xs,
  },
});
