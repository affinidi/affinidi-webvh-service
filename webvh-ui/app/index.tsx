import { useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  ActivityIndicator,
} from "react-native";
import { Link } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { useApi } from "../components/ApiProvider";
import type { HealthResponse } from "../lib/api";

export default function Dashboard() {
  const { isAuthenticated } = useAuth();
  const api = useApi();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [didCount, setDidCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch((e) => setError(e.message));
  }, [api]);

  useEffect(() => {
    if (!isAuthenticated) return;
    api
      .listDids()
      .then((dids) => setDidCount(dids.length))
      .catch(() => {});
  }, [isAuthenticated, api]);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>WebVH Server</Text>

      {error ? (
        <View style={styles.card}>
          <Text style={styles.errorText}>Server unreachable: {error}</Text>
        </View>
      ) : health ? (
        <View style={styles.card}>
          <Text style={styles.cardLabel}>Status</Text>
          <Text style={styles.statusOk}>{health.status}</Text>
          <Text style={styles.cardLabel}>Version</Text>
          <Text style={styles.cardValue}>{health.version}</Text>
        </View>
      ) : (
        <ActivityIndicator color="#7c7cff" size="large" />
      )}

      {isAuthenticated && didCount !== null && (
        <View style={styles.card}>
          <Text style={styles.cardLabel}>Total DIDs</Text>
          <Text style={styles.cardValue}>{didCount}</Text>
        </View>
      )}

      <View style={styles.nav}>
        {!isAuthenticated && (
          <Link href="/login" asChild>
            <Pressable style={styles.button}>
              <Text style={styles.buttonText}>Login</Text>
            </Pressable>
          </Link>
        )}
        <Link href="/dids" asChild>
          <Pressable style={styles.button}>
            <Text style={styles.buttonText}>Manage DIDs</Text>
          </Pressable>
        </Link>
        <Link href="/acl" asChild>
          <Pressable style={styles.button}>
            <Text style={styles.buttonText}>Access Control</Text>
          </Pressable>
        </Link>
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
  title: {
    fontSize: 28,
    fontWeight: "bold",
    color: "#e0e0ff",
    marginBottom: 24,
  },
  card: {
    backgroundColor: "#1a1a2e",
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
    width: "100%",
    maxWidth: 400,
  },
  cardLabel: {
    fontSize: 12,
    color: "#888",
    textTransform: "uppercase",
    marginBottom: 4,
  },
  cardValue: {
    fontSize: 18,
    color: "#e0e0ff",
    marginBottom: 12,
  },
  statusOk: {
    fontSize: 18,
    color: "#4caf50",
    fontWeight: "bold",
    marginBottom: 12,
  },
  errorText: {
    color: "#ef5350",
    fontSize: 14,
  },
  nav: {
    marginTop: 16,
    gap: 12,
    width: "100%",
    maxWidth: 400,
  },
  button: {
    backgroundColor: "#3d3d8e",
    borderRadius: 8,
    paddingVertical: 14,
    paddingHorizontal: 24,
    alignItems: "center",
  },
  buttonText: {
    color: "#e0e0ff",
    fontSize: 16,
    fontWeight: "600",
  },
});
