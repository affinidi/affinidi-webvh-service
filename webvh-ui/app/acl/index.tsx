import { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  Pressable,
  FlatList,
  ActivityIndicator,
  Alert,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import type { AclEntry } from "../../lib/api";

export default function AclManagement() {
  const api = useApi();
  const { isAuthenticated } = useAuth();

  const [entries, setEntries] = useState<AclEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New entry form
  const [newDid, setNewDid] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "owner">("owner");
  const [newLabel, setNewLabel] = useState("");
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    api
      .listAcl()
      .then((data) => {
        setEntries(data.entries);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleCreate = async () => {
    if (!newDid.trim()) return;
    setCreating(true);
    try {
      await api.createAcl(
        newDid.trim(),
        newRole,
        newLabel.trim() || undefined,
      );
      setNewDid("");
      setNewLabel("");
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create ACL entry";
      Alert.alert("Error", msg);
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = (did: string) => {
    Alert.alert(
      "Remove Access",
      `Remove access for ${did}?`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Remove",
          style: "destructive",
          onPress: async () => {
            try {
              await api.deleteAcl(did);
              refresh();
            } catch (e: unknown) {
              const msg = e instanceof Error ? e.message : "Failed to delete";
              Alert.alert("Error", msg);
            }
          },
        },
      ],
    );
  };

  if (!isAuthenticated) {
    return (
      <View style={styles.container}>
        <Text style={styles.hint}>Please log in to manage access control.</Text>
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
    });

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Access Control</Text>

      {/* Add new entry */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Add Entry</Text>
        <TextInput
          style={styles.input}
          placeholder="did:web:example.com"
          placeholderTextColor="#555"
          value={newDid}
          onChangeText={setNewDid}
          autoCapitalize="none"
          autoCorrect={false}
        />
        <View style={styles.roleRow}>
          <Pressable
            style={[
              styles.roleButton,
              newRole === "owner" && styles.roleActive,
            ]}
            onPress={() => setNewRole("owner")}
          >
            <Text
              style={[
                styles.roleText,
                newRole === "owner" && styles.roleTextActive,
              ]}
            >
              Owner
            </Text>
          </Pressable>
          <Pressable
            style={[
              styles.roleButton,
              newRole === "admin" && styles.roleActive,
            ]}
            onPress={() => setNewRole("admin")}
          >
            <Text
              style={[
                styles.roleText,
                newRole === "admin" && styles.roleTextActive,
              ]}
            >
              Admin
            </Text>
          </Pressable>
        </View>
        <TextInput
          style={styles.input}
          placeholder="Label (optional)"
          placeholderTextColor="#555"
          value={newLabel}
          onChangeText={setNewLabel}
        />
        <Pressable
          style={[styles.button, (!newDid.trim() || creating) && styles.disabled]}
          onPress={handleCreate}
          disabled={!newDid.trim() || creating}
        >
          <Text style={styles.buttonText}>
            {creating ? "Adding..." : "Add Entry"}
          </Text>
        </Pressable>
      </View>

      {error && <Text style={styles.errorText}>{error}</Text>}

      {loading ? (
        <ActivityIndicator color="#7c7cff" size="large" style={{ marginTop: 24 }} />
      ) : entries.length === 0 ? (
        <Text style={styles.hint}>No ACL entries configured.</Text>
      ) : (
        <FlatList
          data={entries}
          keyExtractor={(item) => item.did}
          contentContainerStyle={{ gap: 10 }}
          renderItem={({ item }) => (
            <View style={styles.entryCard}>
              <View style={styles.entryInfo}>
                <Text style={styles.entryDid} numberOfLines={1}>
                  {item.did}
                </Text>
                <View style={styles.entryMeta}>
                  <View
                    style={[
                      styles.roleBadge,
                      item.role === "admin" && styles.adminBadge,
                    ]}
                  >
                    <Text style={styles.roleBadgeText}>{item.role}</Text>
                  </View>
                  {item.label && (
                    <Text style={styles.entryLabel}>{item.label}</Text>
                  )}
                  <Text style={styles.entryDate}>
                    {formatDate(item.createdAt)}
                  </Text>
                </View>
              </View>
              <Pressable
                style={styles.deleteButton}
                onPress={() => handleDelete(item.did)}
              >
                <Text style={styles.deleteText}>Remove</Text>
              </Pressable>
            </View>
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
  title: {
    fontSize: 22,
    fontWeight: "bold",
    color: "#e0e0ff",
    marginBottom: 20,
  },
  card: {
    backgroundColor: "#1a1a2e",
    borderRadius: 12,
    padding: 20,
    marginBottom: 20,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#e0e0ff",
    marginBottom: 12,
  },
  input: {
    backgroundColor: "#0f0f23",
    borderColor: "#333",
    borderWidth: 1,
    borderRadius: 8,
    padding: 12,
    color: "#e0e0ff",
    fontSize: 14,
    marginBottom: 12,
  },
  roleRow: {
    flexDirection: "row",
    gap: 10,
    marginBottom: 12,
  },
  roleButton: {
    flex: 1,
    borderColor: "#333",
    borderWidth: 1,
    borderRadius: 8,
    paddingVertical: 10,
    alignItems: "center",
  },
  roleActive: {
    borderColor: "#7c7cff",
    backgroundColor: "#2a2a5e",
  },
  roleText: {
    color: "#888",
    fontWeight: "600",
  },
  roleTextActive: {
    color: "#7c7cff",
  },
  button: {
    backgroundColor: "#3d3d8e",
    borderRadius: 8,
    paddingVertical: 12,
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
  hint: {
    fontSize: 14,
    color: "#aaa",
    textAlign: "center",
    marginTop: 24,
  },
  errorText: {
    color: "#ef5350",
    marginBottom: 12,
  },
  entryCard: {
    backgroundColor: "#1a1a2e",
    borderRadius: 10,
    padding: 14,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
  },
  entryInfo: {
    flex: 1,
    minWidth: 0,
  },
  entryDid: {
    fontSize: 13,
    color: "#e0e0ff",
    fontFamily: "monospace",
    marginBottom: 6,
  },
  entryMeta: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
  },
  roleBadge: {
    backgroundColor: "#2a4a2a",
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  adminBadge: {
    backgroundColor: "#4a2a2a",
  },
  roleBadgeText: {
    fontSize: 11,
    color: "#e0e0ff",
    fontWeight: "bold",
    textTransform: "uppercase",
  },
  entryLabel: {
    fontSize: 13,
    color: "#aaa",
  },
  entryDate: {
    fontSize: 12,
    color: "#666",
  },
  deleteButton: {
    borderColor: "#8e3d3d",
    borderWidth: 1,
    borderRadius: 6,
    paddingHorizontal: 12,
    paddingVertical: 6,
  },
  deleteText: {
    color: "#ef5350",
    fontSize: 12,
    fontWeight: "600",
  },
});
