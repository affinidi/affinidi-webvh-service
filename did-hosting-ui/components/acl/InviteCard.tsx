import { useState } from "react";
import { StyleSheet, Text, View } from "react-native";

import type { CreateInviteResponse, InvitePurpose } from "../../lib/api";
import { notify } from "../../lib/feedback";
import { errorMessage } from "../../lib/errors";
import { invalidateQueries } from "../../lib/query";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { formatRelative } from "../../lib/time";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { CopyButton } from "../CopyButton";
import { Field } from "../Field";
import { SegmentedControl } from "../SegmentedControl";
import { INVITES_KEY } from "./keys";
import { INVITE_ROLES, type InviteRole } from "./roles";
import { Term } from "../Term";

const PURPOSES = [
  { value: "session", label: "Sign-in" },
  { value: "stepUp", label: "Step-up only" },
] as const;

/**
 * Invite by link: generate an enrolment link and a claim code, shown once.
 */
export function InviteCard() {
  const api = useApi();
  const [did, setDid] = useState("");
  const [role, setRole] = useState<InviteRole>("owner");
  const [purpose, setPurpose] = useState<InvitePurpose>("session");
  const [inviting, setInviting] = useState(false);
  const [invite, setInvite] = useState<CreateInviteResponse | null>(null);

  const handleInvite = async () => {
    if (!did.trim() || inviting) return;
    setInviting(true);
    try {
      const resp = await api.createInvite(did.trim(), role, purpose);
      setInvite(resp);
      // Pull in the newly-created invite for the pending list too.
      void invalidateQueries(INVITES_KEY);
    } catch (e: unknown) {
      notify("error", "Could not create the invite", errorMessage(e, "Failed to create invite"));
    } finally {
      setInviting(false);
    }
  };

  const handleClear = () => {
    setInvite(null);
    setDid("");
  };

  return (
    <Card title="Invite by Link" style={styles.card}>
      <Text style={styles.help}>
        Generate an enrollment link and a claim code. Send them over two different channels — the
        link by email, say, and the code by chat or phone: either alone redeems nothing. The invitee
        opens the link, types the code and registers a passkey. A sign-in invite adds them to the
        ACL with the selected role; a step-up invite enrols a passkey that only confirms sensitive
        actions and never signs in.
      </Text>
      <Term term="stepUp" label="What is a step-up passkey?" style={styles.help} />
      {invite ? (
        <View>
          <Text style={styles.fieldLabel}>Enrolment link</Text>
          <View style={styles.valueBlock}>
            <Text style={styles.valueText} selectable numberOfLines={2}>
              {invite.inviteUrl}
            </Text>
          </View>
          <Text style={styles.fieldLabel}>Claim code (send separately)</Text>
          <View style={styles.valueBlock}>
            <Text style={styles.valueText} selectable>
              {invite.claimCode}
            </Text>
          </View>
          <Text style={styles.expiry}>
            {invite.purpose === "stepUp" ? "Step-up passkey. " : ""}
            Expires {formatRelative(invite.expiresAt)}. Shown once: neither the link nor the code
            can be displayed again.
          </Text>
          <View style={styles.actions}>
            <CopyButton
              value={invite.inviteUrl}
              label="Copy Link"
              accessibilityLabel="Copy enrollment link"
              variant="primary"
            />
            <CopyButton
              value={invite.claimCode}
              label="Copy Code"
              accessibilityLabel="Copy claim code"
              variant="primary"
            />
            <Button label="New Invite" variant="secondary" size="sm" onPress={handleClear} />
          </View>
        </View>
      ) : (
        <View>
          <Field
            label="DID to invite"
            placeholder="did:web:example.com"
            value={did}
            onChangeText={setDid}
            autoCapitalize="none"
            autoCorrect={false}
            onSubmit={handleInvite}
          />
          <SegmentedControl
            label="Invite purpose"
            options={PURPOSES}
            value={purpose}
            onChange={setPurpose}
            style={styles.row}
          />
          {purpose === "session" && (
            <SegmentedControl
              label="Role"
              options={INVITE_ROLES}
              value={role}
              onChange={setRole}
              style={styles.row}
            />
          )}
          <Button
            label="Generate Invite"
            busyLabel="Generating..."
            busy={inviting}
            disabled={!did.trim()}
            onPress={handleInvite}
          />
        </View>
      )}
    </Card>
  );
}

const styles = StyleSheet.create({
  card: {
    marginBottom: spacing.xl,
  },
  help: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 19,
    marginBottom: spacing.md,
  },
  fieldLabel: {
    fontSize: 11,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
    marginBottom: 4,
  },
  valueBlock: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.md,
    marginTop: 4,
    marginBottom: spacing.sm,
  },
  valueText: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.teal,
  },
  expiry: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginBottom: spacing.sm,
  },
  actions: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "flex-start",
    gap: spacing.sm,
    marginTop: spacing.xs,
  },
  row: {
    marginBottom: spacing.md,
  },
});
