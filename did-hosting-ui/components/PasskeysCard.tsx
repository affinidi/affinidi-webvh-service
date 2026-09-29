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

import { useCallback, useEffect, useState } from "react";
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { useApi } from "./ApiProvider";
import { getPasskeyCredential } from "../lib/passkey";
import {
  RevocationError,
  completeRevocation,
  startRevocation,
} from "../lib/revoke-flow";
import { showAlert, showConfirm } from "../lib/alert";
import { colors, fonts, radii, spacing } from "../lib/theme";
import type { InvitePurpose, PasskeyCredential } from "../lib/api";

const formatDate = (ts: number) =>
  new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

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
  const [credentials, setCredentials] = useState<PasskeyCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const fetch = subject
      ? api.adminListPasskeys(subject, purpose ?? "session")
      : api.listPasskeys();
    fetch
      .then((creds) => {
        setCredentials(creds);
        setError(null);
      })
      .catch((e) =>
        setError(e instanceof Error ? e.message : "Failed to load passkeys"),
      )
      .finally(() => setLoading(false));
  }, [api, subject, purpose]);

  useEffect(() => {
    load();
  }, [load]);

  const revoke = (cred: PasskeyCredential) => {
    const label = cred.deviceLabel ?? "this passkey";
    showConfirm(
      "Revoke passkey?",
      subject
        ? `Revoke ${label} for ${subject}? If it was their only sign-in passkey, ` +
            `they will need to be re-invited to enrol a replacement.`
        : `Revoke ${label}? You will confirm with another passkey you hold before it's removed.`,
      () => {
        setRevoking(cred.credentialId);
        (async () => {
          try {
            const start = await startRevocation(cred.credentialId, subject);
            await completeRevocation(start, { get: getPasskeyCredential });
            load();
          } catch (e) {
            showAlert(
              "Could not revoke",
              e instanceof RevocationError || e instanceof Error
                ? e.message
                : "Failed to revoke passkey.",
            );
          } finally {
            setRevoking(null);
          }
        })();
      },
    );
  };

  return (
    <View style={styles.card}>
      <Text style={styles.sectionTitle}>{title ?? "Passkeys"}</Text>
      {loading ? (
        <ActivityIndicator color={colors.accent} />
      ) : error ? (
        <Text style={styles.errorText}>{error}</Text>
      ) : credentials.length === 0 ? (
        <Text style={styles.hint}>No passkeys enrolled.</Text>
      ) : (
        credentials.map((c) => (
          <View key={c.credentialId} style={styles.row}>
            <View style={styles.info}>
              <Text style={styles.label}>
                {c.deviceLabel ?? "Unlabelled passkey"}
              </Text>
              <Text style={styles.meta}>
                {purpose ? `${purposeLabel(purpose)} · ` : ""}Enrolled{" "}
                {formatDate(c.registeredAt)}
                {c.lastUsedAt ? ` · last used ${formatDate(c.lastUsedAt)}` : ""}
              </Text>
            </View>
            <Pressable
              style={styles.buttonDanger}
              disabled={revoking === c.credentialId}
              onPress={() => revoke(c)}
            >
              <Text style={styles.buttonDangerText}>
                {revoking === c.credentialId ? "Revoking…" : "Revoke"}
              </Text>
            </Pressable>
          </View>
        ))
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    marginBottom: spacing.lg,
  },
  sectionTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
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
  buttonDanger: {
    backgroundColor: colors.errorBg,
    borderRadius: radii.md,
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
  },
  buttonDangerText: {
    color: colors.error,
    fontSize: 12,
    fontFamily: fonts.semibold,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
  },
});
