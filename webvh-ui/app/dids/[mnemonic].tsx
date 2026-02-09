import { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  Pressable,
  ScrollView,
  ActivityIndicator,
  Alert,
} from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import type { DidStats } from "../../lib/api";

export default function DidDetail() {
  const { mnemonic } = useLocalSearchParams<{ mnemonic: string }>();
  const api = useApi();
  const { isAuthenticated } = useAuth();
  const router = useRouter();

  const [stats, setStats] = useState<DidStats | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [didContent, setDidContent] = useState("");
  const [witnessContent, setWitnessContent] = useState("");
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const loadStats = useCallback(() => {
    if (!mnemonic || !isAuthenticated) return;
    api
      .getStats(mnemonic)
      .then(setStats)
      .catch((e) => setStatsError(e.message));
  }, [api, mnemonic, isAuthenticated]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const handleUploadDid = async () => {
    if (!mnemonic || !didContent.trim()) return;
    setUploading(true);
    try {
      await api.uploadDid(mnemonic, didContent);
      Alert.alert("Success", "DID log uploaded successfully");
      setDidContent("");
      loadStats();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Upload failed";
      Alert.alert("Error", msg);
    } finally {
      setUploading(false);
    }
  };

  const handleUploadWitness = async () => {
    if (!mnemonic || !witnessContent.trim()) return;
    setUploading(true);
    try {
      await api.uploadWitness(mnemonic, witnessContent);
      Alert.alert("Success", "Witness proof uploaded successfully");
      setWitnessContent("");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Upload failed";
      Alert.alert("Error", msg);
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async () => {
    if (!mnemonic) return;
    Alert.alert(
      "Delete DID",
      `Are you sure you want to delete "${mnemonic}"? This cannot be undone.`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Delete",
          style: "destructive",
          onPress: async () => {
            setDeleting(true);
            try {
              await api.deleteDid(mnemonic);
              router.replace("/dids");
            } catch (e: unknown) {
              const msg = e instanceof Error ? e.message : "Delete failed";
              Alert.alert("Error", msg);
              setDeleting(false);
            }
          },
        },
      ],
    );
  };

  if (!isAuthenticated) {
    return (
      <View style={styles.container}>
        <Text style={styles.hint}>Please log in to view DID details.</Text>
      </View>
    );
  }

  const formatDate = (ts: number | null) =>
    ts ? new Date(ts * 1000).toLocaleString() : "Never";

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.title}>{mnemonic}</Text>

      {/* Stats */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Statistics</Text>
        {statsError ? (
          <Text style={styles.errorText}>{statsError}</Text>
        ) : stats ? (
          <View style={styles.statsGrid}>
            <View style={styles.statItem}>
              <Text style={styles.statValue}>{stats.total_resolves}</Text>
              <Text style={styles.statLabel}>Resolves</Text>
            </View>
            <View style={styles.statItem}>
              <Text style={styles.statValue}>{stats.total_updates}</Text>
              <Text style={styles.statLabel}>Updates</Text>
            </View>
            <View style={styles.statItem}>
              <Text style={styles.statSmall}>
                {formatDate(stats.last_resolved_at)}
              </Text>
              <Text style={styles.statLabel}>Last Resolved</Text>
            </View>
            <View style={styles.statItem}>
              <Text style={styles.statSmall}>
                {formatDate(stats.last_updated_at)}
              </Text>
              <Text style={styles.statLabel}>Last Updated</Text>
            </View>
          </View>
        ) : (
          <ActivityIndicator color="#7c7cff" />
        )}
      </View>

      {/* Upload DID log */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Upload DID Log</Text>
        <Text style={styles.hint}>
          Paste the JSONL content for the did.jsonl file.
        </Text>
        <TextInput
          style={styles.textarea}
          placeholder='{"versionId":"1",...}'
          placeholderTextColor="#555"
          value={didContent}
          onChangeText={setDidContent}
          multiline
        />
        <Pressable
          style={[styles.button, (!didContent.trim() || uploading) && styles.disabled]}
          onPress={handleUploadDid}
          disabled={!didContent.trim() || uploading}
        >
          <Text style={styles.buttonText}>
            {uploading ? "Uploading..." : "Upload DID Log"}
          </Text>
        </Pressable>
      </View>

      {/* Upload witness */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Upload Witness Proof</Text>
        <Text style={styles.hint}>
          Paste the JSON content for the witness proof.
        </Text>
        <TextInput
          style={styles.textarea}
          placeholder='{"witness":...}'
          placeholderTextColor="#555"
          value={witnessContent}
          onChangeText={setWitnessContent}
          multiline
        />
        <Pressable
          style={[
            styles.button,
            (!witnessContent.trim() || uploading) && styles.disabled,
          ]}
          onPress={handleUploadWitness}
          disabled={!witnessContent.trim() || uploading}
        >
          <Text style={styles.buttonText}>
            {uploading ? "Uploading..." : "Upload Witness"}
          </Text>
        </Pressable>
      </View>

      {/* Delete */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Danger Zone</Text>
        <Pressable
          style={[styles.dangerButton, deleting && styles.disabled]}
          onPress={handleDelete}
          disabled={deleting}
        >
          <Text style={styles.buttonText}>
            {deleting ? "Deleting..." : "Delete DID"}
          </Text>
        </Pressable>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#0f0f23",
  },
  content: {
    padding: 24,
    maxWidth: 600,
    alignSelf: "center",
    width: "100%",
  },
  title: {
    fontSize: 20,
    fontWeight: "bold",
    color: "#7c7cff",
    fontFamily: "monospace",
    marginBottom: 20,
  },
  card: {
    backgroundColor: "#1a1a2e",
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#e0e0ff",
    marginBottom: 12,
  },
  statsGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 16,
  },
  statItem: {
    minWidth: 120,
  },
  statValue: {
    fontSize: 24,
    fontWeight: "bold",
    color: "#7c7cff",
  },
  statSmall: {
    fontSize: 14,
    color: "#e0e0ff",
  },
  statLabel: {
    fontSize: 12,
    color: "#888",
    textTransform: "uppercase",
    marginTop: 2,
  },
  hint: {
    fontSize: 13,
    color: "#aaa",
    marginBottom: 12,
    lineHeight: 18,
  },
  textarea: {
    backgroundColor: "#0f0f23",
    borderColor: "#333",
    borderWidth: 1,
    borderRadius: 8,
    padding: 12,
    color: "#e0e0ff",
    fontSize: 13,
    fontFamily: "monospace",
    minHeight: 100,
    marginBottom: 12,
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
  dangerButton: {
    backgroundColor: "#8e3d3d",
    borderRadius: 8,
    paddingVertical: 14,
    alignItems: "center",
  },
  buttonText: {
    color: "#e0e0ff",
    fontSize: 14,
    fontWeight: "600",
  },
  errorText: {
    color: "#ef5350",
    fontSize: 14,
  },
});
