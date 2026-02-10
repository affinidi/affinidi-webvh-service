import { useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
} from "react-native";
import { useRouter } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { api } from "../lib/api";
import { getPasskeyCredential } from "../lib/passkey";
import { colors, fonts, radii, spacing } from "../lib/theme";

export default function Login() {
  const { isAuthenticated, logout } = useAuth();
  const { login } = useAuth();
  const router = useRouter();
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);

  const handlePasskeyLogin = async () => {
    setPasskeyLoading(true);
    setPasskeyError(null);
    try {
      const { auth_id, options } = await api.passkeyLoginStart();
      const credential = await getPasskeyCredential(options);
      const result = await api.passkeyLoginFinish(auth_id, credential);
      login(result.access_token);
      router.replace("/");
    } catch (err: any) {
      setPasskeyError(
        err?.message || "Passkey login failed. Passkeys may not be configured."
      );
    } finally {
      setPasskeyLoading(false);
    }
  };

  if (isAuthenticated) {
    return (
      <View style={styles.container}>
        <View style={styles.card}>
          <AffinidiLogo size={36} />
          <Text style={styles.title}>Authenticated</Text>
          <Text style={styles.hint}>
            You are currently logged in.
          </Text>
          <Pressable style={styles.dangerButton} onPress={logout}>
            <Text style={styles.dangerButtonText}>Logout</Text>
          </Pressable>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />
        <Text style={styles.title}>Login</Text>
        <Text style={styles.hint}>
          Use your registered passkey to authenticate with this server.
        </Text>

        <Pressable
          style={[styles.button, passkeyLoading && styles.disabled]}
          onPress={handlePasskeyLogin}
          disabled={passkeyLoading}
        >
          <Text style={styles.buttonText}>
            {passkeyLoading ? "Authenticating..." : "Login with Passkey"}
          </Text>
        </Pressable>

        {passkeyError && (
          <Text style={styles.errorText}>{passkeyError}</Text>
        )}

        <View style={styles.divider}>
          <View style={styles.dividerLine} />
          <Text style={styles.dividerText}>need access?</Text>
          <View style={styles.dividerLine} />
        </View>

        <Text style={styles.cliHint}>
          Ask a server admin to generate an enrollment link:
        </Text>
        <View style={styles.codeBlock}>
          <Text style={styles.codeText} selectable>
            webvh-server invite --did {"<"}your-did{">"} --role admin
          </Text>
        </View>
        <Text style={styles.cliHint}>
          Open the link in your browser to register a passkey, then return
          here to log in.
        </Text>
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
    marginBottom: spacing.lg,
    lineHeight: 20,
  },
  button: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 14,
    alignItems: "center",
  },
  disabled: {
    opacity: 0.5,
  },
  dangerButton: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.error,
    paddingVertical: 14,
    alignItems: "center",
    marginTop: spacing.lg,
  },
  dangerButtonText: {
    color: colors.error,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
  buttonText: {
    color: colors.textOnAccent,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
  divider: {
    flexDirection: "row",
    alignItems: "center",
    marginTop: spacing.xxl,
    marginBottom: spacing.lg,
  },
  dividerLine: {
    flex: 1,
    height: 1,
    backgroundColor: colors.border,
  },
  dividerText: {
    color: colors.textTertiary,
    fontSize: 13,
    fontFamily: fonts.regular,
    marginHorizontal: spacing.md,
  },
  errorText: {
    color: colors.error,
    fontSize: 13,
    fontFamily: fonts.regular,
    marginTop: spacing.md,
    textAlign: "center",
  },
  cliHint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    lineHeight: 19,
    marginBottom: spacing.sm,
  },
  codeBlock: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  codeText: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.teal,
  },
});
