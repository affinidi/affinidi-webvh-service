/**
 * A subject's passkeys, listed and revocable.
 *
 * Two modes, one component:
 * - own (no `subject`): the caller's own inventory, every purpose merged
 *   (`auth/passkey/list`) — used on the account/settings page.
 * - administered (`subject` given): one subject's passkeys of one purpose
 *   (`auth/passkey/admin-list`) — used on the ACL page, so an administrator
 *   can find and revoke a lost or compromised credential, freeing the
 *   subject to be re-invited.
 *
 * Revoking is a re-authentication ceremony, not a bare delete
 * (`lib/revoke-flow.ts`): the browser runs one WebAuthn assertion, from the
 * *caller's own* passkey, before anything is unbound.
 */

import { useState } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";

import type { InvitePurpose, PasskeyCredential } from "../lib/api";
import { confirm, notify } from "../lib/feedback";
import { errorMessage } from "../lib/errors";
import { getPasskeyCredential } from "../lib/passkey";
import { invalidateQueries, useTrustTaskQuery } from "../lib/query";
import { completeRevocation, startRevocation } from "../lib/revoke-flow";
import { colors, fonts, spacing } from "../lib/theme";
import { formatDate } from "../lib/time";
import { useApi } from "./ApiProvider";
import { Button } from "./Button";
import { Card } from "./Card";
import { ErrorWithRetry } from "./QueryState";

/** Every passkey inventory is read under this prefix, so a revocation
 *  refreshes each card that might show the credential. */
const PASSKEYS_KEY = ["passkeys"] as const;

function purposeLabel(purpose: InvitePurpose): string {
  return purpose === "stepUp" ? "Step-up" : "Sign-in";
}

export interface PasskeysCardProps {
  /** Whose passkeys to show. Omit for the caller's own. */
  subject?: string;
  /** Required with `subject`: `auth/passkey/admin-list` is purpose-scoped
   *  by design, so an administrator reads exactly the inventory they asked
   *  for. Ignored (both purposes are shown, merged) for the caller's own. */
  purpose?: InvitePurpose;
  title?: string;
}

export function PasskeysCard({ subject, purpose, title }: PasskeysCardProps) {
  const api = useApi();
  const [revoking, setRevoking] = useState<string | null>(null);
  const listPurpose = purpose ?? "session";
  const passkeys = useTrustTaskQuery<PasskeyCredential[]>(
    subject ? [...PASSKEYS_KEY, "admin", subject, listPurpose] : [...PASSKEYS_KEY, "own"],
    () => (subject ? api.adminListPasskeys(subject, listPurpose) : api.listPasskeys()),
  );
  const credentials = passkeys.data ?? [];

  const revoke = async (cred: PasskeyCredential) => {
    const label = cred.deviceLabel ?? "this passkey";
    const ok = await confirm({
      title: "Revoke passkey?",
      body: subject
        ? `Revoke ${label} for ${subject}? If it was their only sign-in passkey, ` +
          `they will need to be re-invited to enrol a replacement.`
        : `Revoke ${label}? You will confirm with another passkey you hold before it's removed.`,
      confirmLabel: "Revoke passkey",
    });
    if (!ok) return;
    setRevoking(cred.credentialId);
    try {
      const start = await startRevocation(cred.credentialId, subject);
      await completeRevocation(start, { get: getPasskeyCredential });
      await invalidateQueries(PASSKEYS_KEY);
      notify("success", "Passkey revoked", label);
    } catch (e: unknown) {
      notify("error", "Could not revoke the passkey", errorMessage(e, "Failed to revoke passkey."));
    } finally {
      setRevoking(null);
    }
  };

  return (
    <Card title={title ?? "Passkeys"} style={styles.card}>
      {passkeys.loading ? (
        <ActivityIndicator color={colors.accent} aria-label="Loading passkeys" />
      ) : passkeys.error != null && !passkeys.data ? (
        <ErrorWithRetry
          error={passkeys.error}
          what="passkeys"
          onRetry={() => void passkeys.refetch()}
        />
      ) : credentials.length === 0 ? (
        <Text style={styles.hint}>No passkeys enrolled.</Text>
      ) : (
        credentials.map((c) => (
          <View key={c.credentialId} style={styles.row}>
            <View style={styles.info}>
              <Text style={styles.label}>{c.deviceLabel ?? "Unlabelled passkey"}</Text>
              <Text style={styles.meta}>
                {purpose ? `${purposeLabel(purpose)} · ` : ""}Enrolled {formatDate(c.registeredAt)}
                {c.lastUsedAt ? ` · last used ${formatDate(c.lastUsedAt)}` : ""}
              </Text>
            </View>
            <Button
              label="Revoke"
              busyLabel="Revoking…"
              accessibilityLabel={`Revoke ${c.deviceLabel ?? "unlabelled passkey"}`}
              variant="danger"
              size="sm"
              busy={revoking === c.credentialId}
              onPress={() => revoke(c)}
            />
          </View>
        ))
      )}
    </Card>
  );
}

const styles = StyleSheet.create({
  card: {
    marginBottom: spacing.lg,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  info: {
    flex: 1,
    paddingRight: spacing.md,
  },
  label: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textPrimary,
  },
  meta: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginTop: 2,
  },
  hint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
  },
});
