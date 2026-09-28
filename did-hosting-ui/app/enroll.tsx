import { useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  ActivityIndicator,
  Pressable,
  TextInput,
} from "react-native";
import { useRouter, useLocalSearchParams } from "expo-router";
import { AffinidiLogo } from "../components/AffinidiLogo";
import type { RedeemFinishResponse, RedeemStartResponse } from "../lib/api";
import {
  completeRedemption,
  describePurpose,
  startRedemption,
} from "../lib/enrol-flow";
import { createPasskeyCredential, getPasskeyCredential } from "../lib/passkey";
import { colors, fonts, radii, spacing } from "../lib/theme";

type EnrollState =
  | { phase: "code"; error?: string }
  | { phase: "checking" }
  | { phase: "confirm"; start: RedeemStartResponse; error?: string }
  | { phase: "registering"; start: RedeemStartResponse }
  | { phase: "success"; done: RedeemFinishResponse };

/**
 * Redeem a passkey enrolment invite. The link carries the invite token; the
 * claim code was sent separately and is typed here. The page shows whose
 * passkey this will be, and what it may do, before the browser creates it.
 */
export default function Enroll() {
  const { token } = useLocalSearchParams<{ token: string }>();
  const router = useRouter();
  const [claimCode, setClaimCode] = useState("");
  const [label, setLabel] = useState("");
  const [state, setState] = useState<EnrollState>({ phase: "code" });

  const message = (e: unknown, fallback: string) =>
    e instanceof Error && e.message ? e.message : fallback;

  const handleCheck = async () => {
    setState({ phase: "checking" });
    try {
      const start = await startRedemption(token ?? "", claimCode);
      if (start.deviceLabel) setLabel(start.deviceLabel);
      setState({ phase: "confirm", start });
    } catch (e) {
      setState({ phase: "code", error: message(e, "The invite could not be checked.") });
    }
  };

  const handleRegister = async (start: RedeemStartResponse) => {
    setState({ phase: "registering", start });
    try {
      const done = await completeRedemption(
        start,
        { create: createPasskeyCredential, get: getPasskeyCredential },
        label,
      );
      setState({ phase: "success", done });
    } catch (e) {
      setState({
        phase: "confirm",
        start,
        error: message(e, "The passkey could not be registered."),
      });
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />

        {!token && (
          <>
            <Text style={styles.title}>Enrollment Failed</Text>
            <Text style={[styles.hint, { color: colors.error }]}>
              This link has no invite token. Open the link you were sent.
            </Text>
          </>
        )}

        {token && (state.phase === "code" || state.phase === "checking") && (
          <>
            <Text style={styles.title}>Register a Passkey</Text>
            <Text style={styles.hint}>
              Enter the claim code you were sent separately from this link.
            </Text>
            <TextInput
              style={styles.input}
              placeholder="XXXX-XXXX-XXXX"
              placeholderTextColor={colors.textTertiary}
              value={claimCode}
              onChangeText={setClaimCode}
              autoCapitalize="characters"
              autoCorrect={false}
              editable={state.phase === "code"}
            />
            {state.phase === "code" && state.error && (
              <Text style={[styles.hint, { color: colors.error }]}>{state.error}</Text>
            )}
            <Pressable
              style={[
                styles.button,
                (!claimCode.trim() || state.phase === "checking") && styles.disabled,
              ]}
              onPress={handleCheck}
              disabled={!claimCode.trim() || state.phase === "checking"}
            >
              <Text style={styles.buttonText}>
                {state.phase === "checking" ? "Checking..." : "Continue"}
              </Text>
            </Pressable>
          </>
        )}

        {(state.phase === "confirm" || state.phase === "registering") && (
          <>
            <Text style={styles.title}>Confirm Your Passkey</Text>
            <Text style={styles.hint}>This passkey will be bound to:</Text>
            <Text style={styles.subject} selectable>
              {state.start.subject}
            </Text>
            <Text style={styles.hint}>
              It will be {describePurpose(state.start.purpose)}.
              {state.start.uvOptions
                ? " You will first confirm with a passkey you already use here."
                : ""}
            </Text>
            <Text style={styles.hint}>
              If this is not you, close this page and tell whoever sent the invite.
            </Text>
            <TextInput
              style={styles.input}
              placeholder="Device label (optional)"
              placeholderTextColor={colors.textTertiary}
              value={label}
              onChangeText={setLabel}
              maxLength={256}
              editable={state.phase === "confirm"}
            />
            {state.phase === "confirm" && state.error && (
              <Text style={[styles.hint, { color: colors.error }]}>{state.error}</Text>
            )}
            {state.phase === "registering" ? (
              <ActivityIndicator
                color={colors.accent}
                size="large"
                style={{ marginTop: spacing.lg }}
              />
            ) : (
              <Pressable style={styles.button} onPress={() => handleRegister(state.start)}>
                <Text style={styles.buttonText}>Create Passkey</Text>
              </Pressable>
            )}
          </>
        )}

        {state.phase === "success" && (
          <>
            <Text style={styles.title}>Enrollment Complete</Text>
            <Text style={[styles.hint, { color: colors.success }]}>
              Your passkey has been registered for {state.done.subject}.
            </Text>
            {state.done.purpose === "session" ? (
              <Pressable style={styles.button} onPress={() => router.replace("/login")}>
                <Text style={styles.buttonText}>Sign In</Text>
              </Pressable>
            ) : (
              <Text style={styles.hint}>
                It confirms sensitive actions when you are asked to; it does not
                sign you in. You can close this page.
              </Text>
            )}
          </>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: spacing.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgPrimary,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    width: "100%",
    maxWidth: 500,
  },
  title: {
    fontSize: 22,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    marginTop: spacing.lg,
    marginBottom: spacing.md,
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 20,
    marginBottom: spacing.sm,
  },
  subject: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  input: {
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: radii.md,
    padding: spacing.md,
    marginVertical: spacing.md,
    color: colors.textPrimary,
    fontFamily: fonts.regular,
    fontSize: 15,
  },
  button: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    padding: spacing.md,
    alignItems: "center",
    marginTop: spacing.md,
  },
  buttonText: {
    color: colors.textOnAccent,
    fontFamily: fonts.bold,
    fontSize: 15,
  },
  disabled: {
    opacity: 0.5,
  },
});
