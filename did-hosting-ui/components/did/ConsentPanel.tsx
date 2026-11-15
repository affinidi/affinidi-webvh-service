import { StyleSheet, Text, View } from "react-native";

import { colors, fonts, radii, spacing } from "../../lib/theme";
import { digestPrefix, type TaskConsentRequired } from "../../lib/wallet";
import { Button } from "../Button";
import { Heading } from "../Heading";

/**
 * The cross-device approval code, shown wherever a delegated edit is waiting
 * on the user's approval — a document edit, an agent-name change, a did:scid
 * alias change.
 *
 * Every other check in this design assumes an honest device. Only this one
 * survives a compromised one, because only this one moves the comparison into
 * the user's head, across two screens an attacker would have to control both
 * of. That is why it is a code to compare and not a "waiting for approval…"
 * spinner: a spinner is something you wait out; a code is something you check.
 */
export function ConsentPanel({
  consent,
  publishing,
  onPublishNow,
}: {
  consent: TaskConsentRequired | null;
  publishing: boolean;
  onPublishNow: () => void;
}) {
  if (!consent) return null;
  return (
    <View style={styles.panel} role="region" aria-label="Approve this on your device">
      <Heading level={3} style={styles.title}>
        Approve this on your device
      </Heading>
      <Text style={styles.hint}>
        {consent.sideEffects === "destructive"
          ? "This cannot be undone. Your agent has sent the change to your approving device, which will ask you to TYPE the code below. Do not type it from memory of this screen — read it from here, and only approve if the device shows the same code."
          : "Your agent has sent this change to your approving device, with a description of what it will do. Check that the code shown there matches the one below, then approve it."}
      </Text>
      <Text style={styles.code} selectable>
        {digestPrefix(consent.payloadDigest)}
      </Text>
      <Text style={styles.hint}>
        If the codes differ, deny it. A code that does not match means the change your device is
        showing you is not the change that would be made.
      </Text>
      {/* An outstanding approval means the page is listening for the grant. */}
      <Text style={[styles.hint, styles.center]} aria-live="polite">
        Waiting for your approval — this will publish automatically the moment you approve.
      </Text>
      <Button
        variant="secondary"
        label="Publish now"
        busy={publishing}
        busyLabel="Checking..."
        onPress={onPublishNow}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  panel: {
    marginTop: spacing.md,
    padding: spacing.md,
    borderWidth: 1,
    borderColor: colors.warning,
    borderRadius: radii.sm,
    gap: spacing.sm,
  },
  title: {
    marginBottom: 0,
  },
  hint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 18,
  },
  center: {
    textAlign: "center",
  },
  code: {
    fontFamily: fonts.mono,
    fontSize: 28,
    letterSpacing: 6,
    color: colors.textPrimary,
    textAlign: "center",
    paddingVertical: spacing.sm,
  },
});
