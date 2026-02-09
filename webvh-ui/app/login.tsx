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

export default function Login() {
  const { isAuthenticated, login, logout } = useAuth();
  const router = useRouter();
  const [tokenInput, setTokenInput] = useState("");

  const handleLogin = () => {
    const trimmed = tokenInput.trim();
    if (!trimmed) return;
    login(trimmed);
    router.replace("/");
  };

  if (isAuthenticated) {
    return (
      <View style={styles.container}>
        <View style={styles.card}>
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
        <Text style={styles.title}>Authenticate</Text>
        <Text style={styles.hint}>
          Paste a Bearer token obtained via the DIDComm auth flow. The token
          will be stored in your browser and used for API requests.
        </Text>
        <TextInput
          style={styles.input}
          placeholder="eyJhbGciOi..."
          placeholderTextColor="#555"
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
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 24,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#0f0f23",
  },
  card: {
    backgroundColor: "#1a1a2e",
    borderRadius: 12,
    padding: 24,
    width: "100%",
    maxWidth: 500,
  },
  title: {
    fontSize: 22,
    fontWeight: "bold",
    color: "#e0e0ff",
    marginBottom: 12,
  },
  hint: {
    fontSize: 14,
    color: "#aaa",
    marginBottom: 16,
    lineHeight: 20,
  },
  input: {
    backgroundColor: "#0f0f23",
    borderColor: "#333",
    borderWidth: 1,
    borderRadius: 8,
    padding: 12,
    color: "#e0e0ff",
    fontSize: 14,
    fontFamily: "monospace",
    minHeight: 80,
    marginBottom: 16,
  },
  button: {
    backgroundColor: "#3d3d8e",
    borderRadius: 8,
    paddingVertical: 14,
    alignItems: "center",
  },
  disabled: {
    opacity: 0.5,
  },
  dangerButton: {
    backgroundColor: "#8e3d3d",
    borderRadius: 8,
    paddingVertical: 14,
    alignItems: "center",
    marginTop: 16,
  },
  buttonText: {
    color: "#e0e0ff",
    fontSize: 16,
    fontWeight: "600",
  },
});
