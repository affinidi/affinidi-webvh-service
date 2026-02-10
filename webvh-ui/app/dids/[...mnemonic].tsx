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
import { colors, fonts, radii, spacing } from "../../lib/theme";
import type { DidStats } from "../../lib/api";

export default function DidDetail() {
  const { mnemonic: rawMnemonic } = useLocalSearchParams<{ mnemonic: string | string[] }>();
  const mnemonic = Array.isArray(rawMnemonic) ? rawMnemonic.join("/") : rawMnemonic;
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
    const confirmed = window.confirm(
      `Are you sure you want to delete "${mnemonic}"? This cannot be undone.`,
    );
    if (!confirmed) return;
    setDeleting(true);
    try {
      await api.deleteDid(mnemonic);
      router.replace("/dids");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Delete failed";
      Alert.alert("Error", msg);
      setDeleting(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
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
          <ActivityIndicator color={colors.accent} />
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
          placeholderTextColor={colors.textTertiary}
          value={didContent}
          onChangeText={setDidContent}
          multiline
        />
        <Pressable
          style={[
            styles.button,
            (!didContent.trim() || uploading) && styles.disabled,
          ]}
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
          placeholderTextColor={colors.textTertiary}
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
      <View style={[styles.card, styles.dangerCard]}>
        <Text style={styles.sectionTitle}>Danger Zone</Text>
        <Pressable
          style={[styles.dangerButton, deleting && styles.disabled]}
          onPress={handleDelete}
          disabled={deleting}
        >
          <Text style={styles.dangerButtonText}>
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
    backgroundColor: colors.bgPrimary,
  },
  containerCenter: {
    flex: 1,
    backgroundColor: colors.bgPrimary,
    alignItems: "center",
    justifyContent: "center",
  },
  content: {
    padding: spacing.xl,
    maxWidth: 600,
    alignSelf: "center",
    width: "100%",
  },
  title: {
    fontSize: 20,
    fontFamily: fonts.mono,
    fontWeight: "bold",
    color: colors.accent,
    marginBottom: spacing.xl,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    marginBottom: spacing.lg,
  },
  dangerCard: {
    borderColor: "rgba(255, 92, 92, 0.25)",
  },
  sectionTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  statsGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.lg,
  },
  statItem: {
    minWidth: 120,
  },
  statValue: {
    fontSize: 24,
    fontFamily: fonts.bold,
    color: colors.accent,
  },
  statSmall: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textPrimary,
  },
  statLabel: {
    fontSize: 11,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 1,
    marginTop: 2,
  },
  hint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginBottom: spacing.md,
    lineHeight: 18,
  },
  textarea: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.md,
    color: colors.textPrimary,
    fontSize: 13,
    fontFamily: fonts.mono,
    minHeight: 100,
    marginBottom: spacing.md,
  },
  button: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 12,
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
  },
  dangerButtonText: {
    color: colors.error,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
  buttonText: {
    color: colors.textOnAccent,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    fontSize: 14,
  },
});
