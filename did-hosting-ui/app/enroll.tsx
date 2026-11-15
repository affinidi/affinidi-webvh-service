import { useEffect, useState } from "react";
import { View, Text, StyleSheet, ActivityIndicator } from "react-native";
import { useRouter, useLocalSearchParams } from "expo-router";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { Button } from "../components/Button";
import { Field } from "../components/Field";
import { Heading } from "../components/Heading";
import { readPageParam, setNoReferrer, stripPageParam } from "../lib/address-bar";
import type { RedeemFinishResponse, RedeemStartResponse } from "../lib/api";
import {
  completeRedemption,
  describePurpose,
  formatClaimCode,
  startRedemption,
} from "../lib/enrol-flow";
import { errorMessage } from "../lib/errors";
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
  const params = useLocalSearchParams<{ token: string }>();
  // Links carry the token in the fragment (`/enroll#token=…`), which the
  // browser never sends to the web host; links issued before carried it in
  // the query, which the router also exposes. Read once and kept here, then
  // taken out of the address bar and the history entry, so it is not left on
  // screen, in the browser's history or in a bookmark.
  const [token] = useState(() => readPageParam("token") ?? params.token);
  useEffect(() => {
    setNoReferrer();
    stripPageParam("token");
  }, []);
  const router = useRouter();
  const [claimCode, setClaimCode] = useState("");
  const [label, setLabel] = useState("");
  const [state, setState] = useState<EnrollState>({ phase: "code" });

  const handleCheck = async () => {
    if (!claimCode.trim() || state.phase === "checking") return;
    setState({ phase: "checking" });
    try {
      const start = await startRedemption(token ?? "", claimCode);
      if (start.deviceLabel) setLabel(start.deviceLabel);
      setState({ phase: "confirm", start });
    } catch (e: unknown) {
      setState({ phase: "code", error: errorMessage(e, "The invite could not be checked.") });
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
    } catch (e: unknown) {
      setState({
        phase: "confirm",
        start,
        error: errorMessage(e, "The passkey could not be registered."),
      });
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />

        {!token && (
          <>
            <Heading style={styles.title}>Open your enrolment link</Heading>
            <Text style={styles.hint}>
              This page registers a passkey from an invite, and it needs the enrolment link you were
              sent — this address has no invite token in it. Open that link in this browser. If you
              don&apos;t have one, ask an administrator for an invite.
            </Text>
          </>
        )}

        {token && (state.phase === "code" || state.phase === "checking") && (
          <>
            <Heading style={styles.title}>Register a Passkey</Heading>
            <Text style={styles.hint}>
              Enter the claim code you were sent separately from this link, then press Enter or
              Continue.
            </Text>
            <Field
              label="Claim code"
              hint="12 letters and digits, sent to you separately — for example by chat or phone."
              placeholder="XXXX-XXXX-XXXX"
              value={claimCode}
              onChangeText={(v) => setClaimCode(formatClaimCode(v))}
              maxLength={14}
              onSubmit={handleCheck}
              autoCapitalize="characters"
              autoComplete="off"
              autoCorrect={false}
              editable={state.phase === "code"}
              error={state.phase === "code" ? state.error : undefined}
              style={styles.field}
            />
            <Button
              label="Continue"
              busy={state.phase === "checking"}
              busyLabel="Checking..."
              disabled={!claimCode.trim()}
              onPress={handleCheck}
              style={styles.button}
            />
          </>
        )}

        {(state.phase === "confirm" || state.phase === "registering") && (
          <>
            <Heading style={styles.title}>Confirm Your Passkey</Heading>
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
            <Field
              label="Device label (optional)"
              placeholder="Device label (optional)"
              value={label}
              onChangeText={setLabel}
              onSubmit={() => {
                if (state.phase === "confirm") void handleRegister(state.start);
              }}
              maxLength={256}
              editable={state.phase === "confirm"}
              error={state.phase === "confirm" ? state.error : undefined}
              style={styles.field}
            />
            {state.phase === "registering" ? (
              <ActivityIndicator
                color={colors.accent}
                size="large"
                aria-label="Registering the passkey"
                style={{ marginTop: spacing.lg }}
              />
            ) : (
              <Button
                label="Create Passkey"
                onPress={() => handleRegister(state.start)}
                style={styles.button}
              />
            )}
          </>
        )}

        {state.phase === "success" && (
          <>
            <Heading style={styles.title}>Passkey registered</Heading>
            <Text role="status" style={[styles.hint, { color: colors.success }]}>
              Your passkey has been registered for {state.done.subject}.
            </Text>
            {state.done.purpose === "session" ? (
              <Button
                label="Sign in"
                onPress={() => router.replace("/login")}
                style={styles.button}
              />
            ) : (
              <Text style={styles.hint}>
                It confirms sensitive actions when you are asked to; it does not sign you in. You
                can close this page.
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
  error: {
    color: colors.error,
  },
  subject: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  field: {
    marginVertical: spacing.md,
  },
  button: {
    marginTop: spacing.md,
  },
});
