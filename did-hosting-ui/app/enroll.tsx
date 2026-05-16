import { useEffect, useState } from "react";
import { View, Text, StyleSheet, ActivityIndicator } from "react-native";
import { useRouter, useLocalSearchParams } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { api } from "../lib/api";
import { createPasskeyCredential } from "../lib/passkey";
import { colors, fonts, radii, spacing } from "../lib/theme";

type EnrollState =
  | { phase: "registering" }
  | { phase: "success" }
  | { phase: "error"; message: string };

export default function Enroll() {
  const { token } = useLocalSearchParams<{ token: string }>();
  const { login } = useAuth();
  const router = useRouter();
  const [state, setState] = useState<EnrollState>({ phase: "registering" });

  useEffect(() => {
    if (!token) {
      setState({ phase: "error", message: "No enrollment token provided." });
      return;
    }

    let cancelled = false;

    (async () => {
      try {
        // 1. Start enrollment
        const { registration_id, options } =
          await api.passkeyEnrollStart(token);

        if (cancelled) return;

        // 2. Create credential in browser
        const credential = await createPasskeyCredential(options);

        if (cancelled) return;

        // 3. Finish enrollment
        const result = await api.passkeyEnrollFinish(
          registration_id,
          credential,
        );

        if (cancelled) return;

        // 4. Save token and redirect
        login(result.access_token);
        setState({ phase: "success" });

        setTimeout(() => {
          if (!cancelled) router.replace("/");
        }, 1500);
      } catch (err: any) {
        if (!cancelled) {
          const msg =
            err?.message || "Enrollment failed. The link may be expired or already used.";
          setState({ phase: "error", message: msg });
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />

        {state.phase === "registering" && (
          <>
            <Text style={styles.title}>Registering Passkey</Text>
            <Text style={styles.hint}>
              Follow your browser's prompts to register a passkey for this
              server.
            </Text>
            <ActivityIndicator
              color={colors.accent}
              size="large"
              style={{ marginTop: spacing.lg }}
            />
          </>
        )}

        {state.phase === "success" && (
          <>
            <Text style={styles.title}>Enrollment Complete</Text>
            <Text style={[styles.hint, { color: colors.success }]}>
              Your passkey has been registered. Redirecting to dashboard...
            </Text>
          </>
        )}

        {state.phase === "error" && (
          <>
            <Text style={styles.title}>Enrollment Failed</Text>
            <Text style={[styles.hint, { color: colors.error }]}>
              {state.message}
            </Text>
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
  },
});
