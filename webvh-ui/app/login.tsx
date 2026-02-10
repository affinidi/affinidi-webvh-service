import { useState } from "react";
import {
  View,
  Text,
  TextInput,
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
  const { isAuthenticated, login, logout } = useAuth();
  const router = useRouter();
  const [tokenInput, setTokenInput] = useState("");
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);

  const handleLogin = () => {
    const trimmed = tokenInput.trim();
    if (!trimmed) return;
    login(trimmed);
    router.replace("/");
  };

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
            You are currently logged in with a Bearer token.
          </Text>
          <Pressable style={styles.dangerButton} onPress={logout}>
            <Text style={styles.buttonText}>Logout</Text>
          </Pressable>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />
        <Text style={styles.title}>Authenticate</Text>
        <Text style={styles.hint}>
          Paste a Bearer token obtained via the DIDComm auth flow. The token
          will be stored in your browser and used for API requests.
        </Text>
        <TextInput
          style={styles.input}
          placeholder="eyJhbGciOi..."
          placeholderTextColor={colors.textTertiary}
          value={tokenInput}
          onChangeText={setTokenInput}
          multiline
          autoCapitalize="none"
          autoCorrect={false}
        />
        <Pressable
          style={[styles.button, !tokenInput.trim() && styles.disabled]}
          onPress={handleLogin}
          disabled={!tokenInput.trim()}
        >
          <Text style={styles.buttonText}>Save Token</Text>
        </Pressable>

        <View style={styles.divider}>
          <View style={styles.dividerLine} />
          <Text style={styles.dividerText}>or</Text>
          <View style={styles.dividerLine} />
        </View>

        <Pressable
          style={[styles.passkeyButton, passkeyLoading && styles.disabled]}
          onPress={handlePasskeyLogin}
          disabled={passkeyLoading}
        >
          <Text style={styles.passkeyButtonText}>
            {passkeyLoading ? "Authenticating..." : "Login with Passkey"}
          </Text>
        </Pressable>

        {passkeyError && (
          <Text style={styles.errorText}>{passkeyError}</Text>
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
    marginBottom: spacing.lg,
    lineHeight: 20,
  },
  input: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.md,
    color: colors.textPrimary,
    fontSize: 14,
    fontFamily: fonts.mono,
    minHeight: 80,
    marginBottom: spacing.lg,
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
  buttonText: {
    color: colors.textOnAccent,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
  divider: {
    flexDirection: "row",
    alignItems: "center",
    marginVertical: spacing.lg,
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
  passkeyButton: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.accent,
    paddingVertical: 14,
    alignItems: "center",
  },
  passkeyButtonText: {
    color: colors.accent,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
  errorText: {
    color: colors.error,
    fontSize: 13,
    fontFamily: fonts.regular,
    marginTop: spacing.md,
    textAlign: "center",
  },
});
