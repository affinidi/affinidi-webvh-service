import { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  FlatList,
  ActivityIndicator,
  Alert,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import type { DidRecord } from "../../lib/api";

export default function DidList() {
  const api = useApi();
  const { isAuthenticated } = useAuth();
  const [dids, setDids] = useState<DidRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    api
      .listDids()
      .then((data) => {
        setDids(data);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await api.createDid();
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create DID";
      Alert.alert("Error", msg);
    } finally {
      setCreating(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <View style={styles.container}>
        <Text style={styles.hint}>Please log in to manage DIDs.</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.button}>
            <Text style={styles.buttonText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  const formatDate = (ts: number) =>
    new Date(ts * 1000).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Your DIDs</Text>
        <Pressable
          style={[styles.button, creating && styles.disabled]}
          onPress={handleCreate}
          disabled={creating}
        >
          <Text style={styles.buttonText}>
            {creating ? "Creating..." : "Request New DID"}
          </Text>
        </Pressable>
      </View>

      {error && <Text style={styles.errorText}>{error}</Text>}

      {loading ? (
        <ActivityIndicator color="#7c7cff" size="large" style={{ marginTop: 32 }} />
      ) : dids.length === 0 ? (
        <Text style={styles.hint}>
          No DIDs yet. Create one to get started.
        </Text>
      ) : (
        <FlatList
          data={dids}
          keyExtractor={(item) => item.mnemonic}
          contentContainerStyle={{ gap: 12 }}
          renderItem={({ item }) => (
            <Link href={`/dids/${item.mnemonic}`} asChild>
              <Pressable style={styles.card}>
                <Text style={styles.mnemonic}>{item.mnemonic}</Text>
                <View style={styles.meta}>
                  <Text style={styles.metaText}>
                    Versions: {item.versionCount}
                  </Text>
                  <Text style={styles.metaText}>
                    Updated: {formatDate(item.updatedAt)}
                  </Text>
                </View>
              </Pressable>
            </Link>
          )}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 24,
    backgroundColor: "#0f0f23",
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 20,
    flexWrap: "wrap",
    gap: 12,
  },
  title: {
    fontSize: 22,
    fontWeight: "bold",
    color: "#e0e0ff",
  },
  card: {
    backgroundColor: "#1a1a2e",
    borderRadius: 12,
    padding: 16,
  },
  mnemonic: {
    fontSize: 16,
    fontWeight: "600",
    color: "#7c7cff",
    fontFamily: "monospace",
    marginBottom: 8,
  },
  meta: {
    flexDirection: "row",
    gap: 16,
  },
  metaText: {
    fontSize: 13,
    color: "#888",
  },
  hint: {
    fontSize: 14,
    color: "#aaa",
    textAlign: "center",
    marginTop: 32,
  },
  errorText: {
    color: "#ef5350",
    marginBottom: 12,
  },
  button: {
    backgroundColor: "#3d3d8e",
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 20,
    alignItems: "center",
  },
  disabled: {
    opacity: 0.5,
  },
  buttonText: {
    color: "#e0e0ff",
    fontSize: 14,
    fontWeight: "600",
  },
});
