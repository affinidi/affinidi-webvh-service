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
import { Link, useLocalSearchParams, useRouter } from "expo-router";
import * as Clipboard from "expo-clipboard";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import type { DidStats, DidDetailResponse, LogEntryInfo } from "../../lib/api";

export default function DidDetail() {
  const { mnemonic: rawMnemonic } = useLocalSearchParams<{ mnemonic: string | string[] }>();
  const mnemonic = Array.isArray(rawMnemonic) ? rawMnemonic.join("/") : rawMnemonic;
  const api = useApi();
  const { isAuthenticated } = useAuth();
  const router = useRouter();

  const [stats, setStats] = useState<DidStats | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [didDetail, setDidDetail] = useState<DidDetailResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [didContent, setDidContent] = useState("");
  const [witnessContent, setWitnessContent] = useState("");
  const [logEntries, setLogEntries] = useState<LogEntryInfo[]>([]);
  const [selectedVersion, setSelectedVersion] = useState(-1);
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const loadData = useCallback(() => {
    if (!mnemonic || !isAuthenticated) return;
    api
      .getStats(mnemonic)
      .then(setStats)
      .catch((e) => setStatsError(e.message));
    api
      .getDid(mnemonic)
      .then(setDidDetail)
      .catch(() => {});
    api
      .getDidLog(mnemonic)
      .then((entries) => {
        setLogEntries(entries);
        setSelectedVersion(entries.length - 1);
      })
      .catch(() => {});
  }, [api, mnemonic, isAuthenticated]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCopyDidId = async () => {
    if (!didDetail?.didId) return;
    await Clipboard.setStringAsync(didDetail.didId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleUploadDid = async () => {
    if (!mnemonic || !didContent.trim()) return;
    setUploading(true);
    try {
      await api.uploadDid(mnemonic, didContent);
      Alert.alert("Success", "DID log uploaded successfully");
      setDidContent("");
      loadData();
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
        <Link href="/login" asChild>
          <Pressable style={styles.button}>
            <Text style={styles.buttonText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  const formatDate = (ts: number | null) =>
    ts ? new Date(ts * 1000).toLocaleString() : "Never";

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.narrow}>
        <Text style={styles.title}>
          {mnemonic === ".well-known" ? "Root DID (.well-known)" : mnemonic}
        </Text>

        {/* DID ID directly under title */}
        {didDetail && (
          didDetail.didId ? (
            <View style={styles.didIdRow}>
              <Text style={styles.didIdText} numberOfLines={1}>
                {didDetail.didId}
              </Text>
              <Pressable style={styles.copyButton} onPress={handleCopyDidId}>
                <Text style={styles.copyButtonText}>
                  {copied ? "Copied" : "Copy"}
                </Text>
              </Pressable>
            </View>
          ) : (
            <Text style={styles.pendingText}>Pending upload</Text>
          )
        )}
        {/* Owner */}
        {didDetail && (
          <Text style={styles.ownerText}>Owner: {didDetail.owner}</Text>
        )}

        {/* Stats */}
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>Statistics</Text>
          {statsError ? (
            <Text style={styles.errorText}>{statsError}</Text>
          ) : stats ? (
            <View style={styles.statsGrid}>
              <View style={styles.statItem}>
                <Text style={styles.statValue}>{stats.total_resolves.toLocaleString()}</Text>
                <Text style={styles.statLabel}>Resolves</Text>
              </View>
              <View style={styles.statItem}>
                <Text style={styles.statValue}>{stats.total_updates.toLocaleString()}</Text>
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

        {/* DID Details — parsed from log entries */}
        {didDetail?.log && (
          <View style={styles.card}>
            <Text style={styles.sectionTitle}>DID Details</Text>
            <View style={styles.detailsGrid}>
              <View style={styles.detailRow}>
                <Text style={styles.detailLabel}>Version</Text>
                <Text style={styles.detailValue}>
                  {didDetail.log.latestVersionId ?? "-"}
                </Text>
              </View>
              {didDetail.log.latestVersionTime && (
                <View style={styles.detailRow}>
                  <Text style={styles.detailLabel}>Version Time</Text>
                  <Text style={styles.detailValue}>
                    {new Date(didDetail.log.latestVersionTime).toLocaleString()}
                  </Text>
                </View>
              )}
              {didDetail.log.method && (
                <View style={styles.detailRow}>
                  <Text style={styles.detailLabel}>Method</Text>
                  <Text style={styles.detailValueMono}>
                    {didDetail.log.method}
                  </Text>
                </View>
              )}
              <View style={styles.detailRow}>
                <Text style={styles.detailLabel}>Log Entries</Text>
                <Text style={styles.detailValue}>
                  {didDetail.log.logEntryCount.toLocaleString()}
                </Text>
              </View>
              {didDetail.log.ttl != null && (
                <View style={styles.detailRow}>
                  <Text style={styles.detailLabel}>TTL</Text>
                  <Text style={styles.detailValue}>
                    {didDetail.log.ttl}s
                  </Text>
                </View>
              )}
            </View>

            <Text style={[styles.sectionTitle, { marginTop: spacing.lg }]}>
              Options
            </Text>
            <View style={styles.optionsGrid}>
              <View style={styles.optionItem}>
                <Text
                  style={
                    didDetail.log.portable
                      ? styles.optionEnabled
                      : styles.optionDisabled
                  }
                >
                  {didDetail.log.portable ? "Yes" : "No"}
                </Text>
                <Text style={styles.statLabel}>Portable</Text>
              </View>
              <View style={styles.optionItem}>
                <Text
                  style={
                    didDetail.log.preRotation
                      ? styles.optionEnabled
                      : styles.optionDisabled
                  }
                >
                  {didDetail.log.preRotation ? "Yes" : "No"}
                </Text>
                <Text style={styles.statLabel}>Pre-rotation</Text>
              </View>
              <View style={styles.optionItem}>
                <Text
                  style={
                    didDetail.log.witnesses
                      ? styles.optionEnabled
                      : styles.optionDisabled
                  }
                >
                  {didDetail.log.witnesses
                    ? `${didDetail.log.witnessThreshold}/${didDetail.log.witnessCount}`
                    : "None"}
                </Text>
                <Text style={styles.statLabel}>Witnesses</Text>
              </View>
              <View style={styles.optionItem}>
                <Text
                  style={
                    didDetail.log.watchers
                      ? styles.optionEnabled
                      : styles.optionDisabled
                  }
                >
                  {didDetail.log.watchers
                    ? String(didDetail.log.watcherCount)
                    : "None"}
                </Text>
                <Text style={styles.statLabel}>Watchers</Text>
              </View>
              <View style={styles.optionItem}>
                <Text
                  style={
                    didDetail.log.deactivated
                      ? styles.optionDeactivated
                      : styles.optionEnabled
                  }
                >
                  {didDetail.log.deactivated ? "Yes" : "No"}
                </Text>
                <Text style={styles.statLabel}>Deactivated</Text>
              </View>
            </View>
          </View>
        )}

      </View>

      {/* DID Document viewer — full width */}
      {logEntries.length > 0 && (
        <View style={styles.wideCard}>
          <Text style={styles.sectionTitle}>DID Document</Text>
          <View style={styles.versionRow}>
            <Text style={styles.detailLabel}>Version</Text>
            <View style={styles.selectWrapper}>
              <select
                value={selectedVersion}
                onChange={(e: any) => setSelectedVersion(Number(e.target.value))}
                style={{
                  backgroundColor: colors.bgPrimary,
                  color: colors.textPrimary,
                  border: `1px solid ${colors.border}`,
                  borderRadius: radii.sm,
                  padding: "6px 10px",
                  fontFamily: fonts.mono,
                  fontSize: 13,
                  width: "100%",
                }}
              >
                {logEntries.map((entry, idx) => (
                  <option key={idx} value={idx}>
                    Version {idx + 1}
                    {entry.versionId ? ` — ${entry.versionId}` : ""}
                    {entry.versionTime ? ` (${entry.versionTime})` : ""}
                  </option>
                ))}
              </select>
            </View>
          </View>
          {logEntries[selectedVersion]?.state && (
            <div style={{
              backgroundColor: colors.bgPrimary,
              border: `1px solid ${colors.border}`,
              borderRadius: radii.sm,
              overflow: "auto",
              maxHeight: 500,
              padding: spacing.md,
            }}>
              <pre style={{
                margin: 0,
                fontFamily: fonts.mono,
                fontSize: 12,
                lineHeight: "18px",
                color: colors.textPrimary,
                whiteSpace: "pre",
              }}>
                {JSON.stringify(logEntries[selectedVersion].state, null, 2)}
              </pre>
            </div>
          )}
        </View>
      )}

      <View style={styles.narrow}>
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
  },
  narrow: {
    maxWidth: 600,
    alignSelf: "center",
    width: "100%",
  },
  title: {
    fontSize: 20,
    fontFamily: fonts.mono,
    fontWeight: "bold",
    color: colors.accent,
    marginBottom: spacing.sm,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    marginBottom: spacing.lg,
  },
  wideCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    marginBottom: spacing.lg,
    width: "100%",
    maxWidth: 1200,
    alignSelf: "center",
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
  didIdRow: {
    flexDirection: "row",
    alignItems: "center",
    alignSelf: "flex-start",
    gap: spacing.sm,
    marginBottom: spacing.xl,
  },
  didIdText: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.teal,
  },
  copyButton: {
    borderRadius: radii.sm,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 4,
    paddingHorizontal: spacing.sm,
  },
  copyButtonText: {
    fontSize: 13,
    fontFamily: fonts.semibold,
    color: colors.textSecondary,
  },
  pendingText: {
    fontSize: 14,
    fontFamily: fonts.medium,
    color: colors.warning,
    marginBottom: spacing.xl,
  },
  ownerText: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textSecondary,
    marginBottom: spacing.lg,
  },
  detailsGrid: {
    gap: spacing.sm,
  },
  detailRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  detailLabel: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
  },
  detailValue: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textPrimary,
  },
  detailValueMono: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
  },
  optionsGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.lg,
  },
  optionItem: {
    minWidth: 90,
  },
  optionEnabled: {
    fontSize: 16,
    fontFamily: fonts.bold,
    color: colors.success,
  },
  optionDisabled: {
    fontSize: 16,
    fontFamily: fonts.bold,
    color: colors.textTertiary,
  },
  optionDeactivated: {
    fontSize: 16,
    fontFamily: fonts.bold,
    color: colors.error,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    fontSize: 14,
  },
  versionRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    marginBottom: spacing.md,
  },
  selectWrapper: {
    flex: 1,
  },
});
