import { useEffect, useState, useCallback, useRef } from "react";
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  Pressable,
  ScrollView,
  ActivityIndicator,
} from "react-native";
import { Link, useLocalSearchParams, useRouter } from "expo-router";
import * as Clipboard from "expo-clipboard";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { UsageChart } from "../../components/UsageChart";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { showAlert, showConfirm } from "../../lib/alert";
import type { DidStats, DidDetailResponse, LogEntryInfo, WatcherSyncStatus } from "../../lib/api";

// ---------------------------------------------------------------------------
// ChipInput — inline component for tag-style multi-value inputs
// ---------------------------------------------------------------------------

function ChipInput({
  values,
  onChange,
  suggestions,
  placeholder,
  readOnly,
}: {
  values: string[];
  onChange: (v: string[]) => void;
  suggestions?: string[];
  placeholder?: string;
  readOnly?: boolean;
}) {
  const [input, setInput] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const filtered = (suggestions ?? []).filter(
    (s) =>
      !values.includes(s) &&
      s.toLowerCase().includes(input.toLowerCase()),
  );

  const addValue = (v: string) => {
    const trimmed = v.trim();
    if (trimmed && !values.includes(trimmed)) {
      onChange([...values, trimmed]);
    }
    setInput("");
    setShowDropdown(false);
  };

  const removeValue = (v: string) => {
    onChange(values.filter((x) => x !== v));
  };

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div ref={wrapperRef} style={{ position: "relative" }}>
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 6,
          alignItems: "center",
          minHeight: 36,
        }}
      >
        {values.map((v) => (
          <span
            key={v}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              backgroundColor: colors.bgTertiary,
              border: `1px solid ${colors.border}`,
              borderRadius: radii.full,
              padding: "3px 10px",
              fontSize: 12,
              fontFamily: fonts.mono,
              color: colors.textPrimary,
            }}
          >
            <span
              style={{
                maxWidth: 280,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {v}
            </span>
            {!readOnly && (
              <button
                onClick={() => removeValue(v)}
                style={{
                  background: "none",
                  border: "none",
                  color: colors.textTertiary,
                  cursor: "pointer",
                  fontSize: 14,
                  padding: 0,
                  lineHeight: 1,
                }}
              >
                x
              </button>
            )}
          </span>
        ))}
        {!readOnly && (
          <input
            type="text"
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setShowDropdown(true);
            }}
            onFocus={() => setShowDropdown(true)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addValue(input);
              }
            }}
            placeholder={values.length === 0 ? placeholder : ""}
            style={{
              flex: 1,
              minWidth: 120,
              background: "none",
              border: "none",
              outline: "none",
              color: colors.textPrimary,
              fontFamily: fonts.mono,
              fontSize: 12,
              padding: "4px 0",
            }}
          />
        )}
        {readOnly && values.length === 0 && (
          <span
            style={{
              color: colors.textTertiary,
              fontSize: 12,
              fontFamily: fonts.regular,
            }}
          >
            None
          </span>
        )}
      </div>
      {showDropdown && filtered.length > 0 && !readOnly && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            right: 0,
            zIndex: 10,
            backgroundColor: colors.bgSecondary,
            border: `1px solid ${colors.border}`,
            borderRadius: radii.sm,
            maxHeight: 160,
            overflowY: "auto",
            marginTop: 4,
          }}
        >
          {filtered.map((s) => (
            <div
              key={s}
              onClick={() => addValue(s)}
              style={{
                padding: "6px 10px",
                fontSize: 12,
                fontFamily: fonts.mono,
                color: colors.textPrimary,
                cursor: "pointer",
                borderBottom: `1px solid ${colors.border}`,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              onMouseEnter={(e) => {
                (e.target as HTMLDivElement).style.backgroundColor =
                  colors.bgTertiary;
              }}
              onMouseLeave={(e) => {
                (e.target as HTMLDivElement).style.backgroundColor =
                  "transparent";
              }}
            >
              {s}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

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
  const [rollingBack, setRollingBack] = useState(false);
  const [loadingRaw, setLoadingRaw] = useState(false);
  const [editingDoc, setEditingDoc] = useState(false);
  const [docEditValue, setDocEditValue] = useState("");
  const [editingParams, setEditingParams] = useState(false);
  const [paramWatchers, setParamWatchers] = useState<string[]>([]);
  const [paramWitnesses, setParamWitnesses] = useState<string[]>([]);
  const [paramAlsoKnownAs, setParamAlsoKnownAs] = useState<string[]>([]);
  const [paramPortable, setParamPortable] = useState(false);
  const [paramTtl, setParamTtl] = useState<string>("");
  const [knownWatcherUrls, setKnownWatcherUrls] = useState<string[]>([]);

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
    api
      .getServices()
      .then((s) => setKnownWatcherUrls(s.watcherUrls))
      .catch(() => {});
  }, [api, mnemonic, isAuthenticated]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Sync parameter editor state when detail or log entries change
  useEffect(() => {
    if (!logEntries.length) return;
    const latest = logEntries[logEntries.length - 1];
    const params = latest?.parameters;
    const state = latest?.state;

    if (params) {
      setParamPortable(params.portable ?? false);
      setParamTtl(params.ttl != null ? String(params.ttl) : "");

      const watchers: string[] = Array.isArray(params.watchers)
        ? params.watchers.filter((w: unknown) => typeof w === "string")
        : [];
      setParamWatchers(watchers);

      const witnesses: string[] =
        params.witness?.witnesses
          ?.map((w: any) => w.id)
          .filter((id: unknown) => typeof id === "string") ?? [];
      setParamWitnesses(witnesses);
    }

    if (state) {
      const aka: string[] = Array.isArray(state.alsoKnownAs)
        ? state.alsoKnownAs.filter((a: unknown) => typeof a === "string")
        : [];
      setParamAlsoKnownAs(aka);
    }
  }, [logEntries]);

  const handleCopyDidId = async () => {
    if (!didDetail?.didId) return;
    await Clipboard.setStringAsync(didDetail.didId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleLoadCurrentJsonl = async () => {
    if (!mnemonic) return;
    setLoadingRaw(true);
    try {
      const raw = await api.getRawLog(mnemonic);
      setDidContent(raw);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load raw log";
      showAlert("Error", msg);
    } finally {
      setLoadingRaw(false);
    }
  };

  const handleUploadDid = async () => {
    if (!mnemonic || !didContent.trim()) return;
    setUploading(true);
    try {
      await api.uploadDid(mnemonic, didContent);
      showAlert("Success", "DID log uploaded successfully");
      setDidContent("");
      loadData();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Upload failed";
      showAlert("Error", msg);
    } finally {
      setUploading(false);
    }
  };

  const handleUploadWitness = async () => {
    if (!mnemonic || !witnessContent.trim()) return;
    setUploading(true);
    try {
      await api.uploadWitness(mnemonic, witnessContent);
      showAlert("Success", "Witness proof uploaded successfully");
      setWitnessContent("");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Upload failed";
      showAlert("Error", msg);
    } finally {
      setUploading(false);
    }
  };

  const handleRollback = () => {
    if (!mnemonic) return;
    showConfirm(
      "Rollback Last Entry",
      "Are you sure you want to remove the last log entry? This cannot be undone.",
      async () => {
        setRollingBack(true);
        try {
          const updated = await api.rollbackDid(mnemonic);
          setDidDetail(updated);
          loadData();
          showAlert("Success", "Last log entry has been rolled back");
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : "Rollback failed";
          showAlert("Error", msg);
        } finally {
          setRollingBack(false);
        }
      },
    );
  };

  const handleDelete = async () => {
    if (!mnemonic) return;
    showConfirm(
      "Delete DID",
      `Are you sure you want to delete "${mnemonic}"? This cannot be undone.`,
      async () => {
        setDeleting(true);
        try {
          await api.deleteDid(mnemonic);
          router.replace("/dids");
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : "Delete failed";
          showAlert("Error", msg);
          setDeleting(false);
        }
      },
    );
  };

  const handleToggleDocEdit = () => {
    if (!editingDoc && logEntries[selectedVersion]?.state) {
      setDocEditValue(
        JSON.stringify(logEntries[selectedVersion].state, null, 2),
      );
    }
    setEditingDoc(!editingDoc);
  };

  const handleCopyDocToUpload = async () => {
    if (!mnemonic) return;
    setLoadingRaw(true);
    try {
      const raw = await api.getRawLog(mnemonic);
      setDidContent(raw);
      setEditingDoc(false);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load raw log";
      showAlert("Error", msg);
    } finally {
      setLoadingRaw(false);
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

  const logEntryCount = didDetail?.log?.logEntryCount ?? 0;

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.wide}>
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

        {/* Watcher Sync */}
        {didDetail?.watcherSync && didDetail.watcherSync.length > 0 && (
          <View style={styles.card}>
            <Text style={styles.sectionTitle}>Watcher Sync</Text>
            {didDetail.watcherSync.map((ws: WatcherSyncStatus, idx: number) => {
              const synced =
                ws.ok &&
                ws.lastSyncedVersionId != null &&
                ws.lastSyncedVersionId === didDetail.log?.latestVersionId;
              return (
                <View key={idx} style={styles.watcherRow}>
                  <View
                    style={[
                      styles.watcherDot,
                      { backgroundColor: synced ? colors.success : colors.error },
                    ]}
                  />
                  <View style={styles.watcherInfo}>
                    <Text style={styles.watcherUrl} numberOfLines={1}>
                      {ws.watcherUrl}
                    </Text>
                    {ws.lastSyncedVersionId && (
                      <Text style={styles.watcherMeta}>
                        Synced: {ws.lastSyncedVersionId}
                      </Text>
                    )}
                    {ws.lastError && (
                      <Text style={styles.watcherError}>{ws.lastError}</Text>
                    )}
                  </View>
                </View>
              );
            })}
          </View>
        )}

        {/* Usage chart */}
        {mnemonic && <UsageChart mnemonic={mnemonic} />}

        {/* DID Document viewer / editor */}
        {logEntries.length > 0 && (
          <View style={styles.card}>
            <View style={styles.sectionTitleRow}>
              <Text style={styles.sectionTitle}>DID Document</Text>
              <View style={styles.sectionActions}>
                <Pressable
                  style={styles.smallButton}
                  onPress={handleToggleDocEdit}
                >
                  <Text style={styles.smallButtonText}>
                    {editingDoc ? "Cancel" : "Edit"}
                  </Text>
                </Pressable>
                {editingDoc && (
                  <Pressable
                    style={[styles.smallButton, loadingRaw && styles.disabled]}
                    onPress={handleCopyDocToUpload}
                    disabled={loadingRaw}
                  >
                    <Text style={styles.smallButtonText}>
                      {loadingRaw ? "Loading..." : "Copy to Upload"}
                    </Text>
                  </Pressable>
                )}
              </View>
            </View>
            <View style={styles.versionRow}>
              <Text style={styles.detailLabel}>Version</Text>
              <View style={styles.selectWrapper}>
                <select
                  value={selectedVersion}
                  onChange={(e: any) => {
                    const v = Number(e.target.value);
                    setSelectedVersion(v);
                    if (editingDoc && logEntries[v]?.state) {
                      setDocEditValue(
                        JSON.stringify(logEntries[v].state, null, 2),
                      );
                    }
                  }}
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
            {editingDoc ? (
              <TextInput
                style={[styles.textarea, { minHeight: 300 }]}
                value={docEditValue}
                onChangeText={setDocEditValue}
                multiline
              />
            ) : (
              logEntries[selectedVersion]?.state && (
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
              )
            )}
          </View>
        )}

        {/* Parameters editor */}
        {logEntries.length > 0 && (
          <View style={styles.card}>
            <View style={styles.sectionTitleRow}>
              <Text style={styles.sectionTitle}>Parameters</Text>
              <Pressable
                style={styles.smallButton}
                onPress={() => setEditingParams(!editingParams)}
              >
                <Text style={styles.smallButtonText}>
                  {editingParams ? "Done" : "Edit Parameters"}
                </Text>
              </Pressable>
            </View>
            {!editingParams && (
              <Text style={styles.hint}>
                View and configure parameters for the next log entry.
                Editing is informational — use these values when constructing signed JSONL.
              </Text>
            )}

            <View style={styles.paramField}>
              <Text style={styles.paramLabel}>Watchers</Text>
              <ChipInput
                values={paramWatchers}
                onChange={setParamWatchers}
                suggestions={knownWatcherUrls}
                placeholder="Add watcher URL..."
                readOnly={!editingParams}
              />
            </View>

            <View style={styles.paramField}>
              <Text style={styles.paramLabel}>Witnesses</Text>
              <ChipInput
                values={paramWitnesses}
                onChange={setParamWitnesses}
                placeholder="Add witness DID..."
                readOnly={!editingParams}
              />
            </View>

            <View style={styles.paramField}>
              <Text style={styles.paramLabel}>Also Known As</Text>
              <ChipInput
                values={paramAlsoKnownAs}
                onChange={setParamAlsoKnownAs}
                placeholder="Add alternate identifier..."
                readOnly={!editingParams}
              />
            </View>

            <View style={[styles.paramField, { flexDirection: "row", alignItems: "center", gap: spacing.lg }]}>
              <View style={{ flexDirection: "row", alignItems: "center", gap: spacing.sm }}>
                <Text style={styles.paramLabel}>Portable</Text>
                <input
                  type="checkbox"
                  checked={paramPortable}
                  onChange={(e) => setParamPortable(e.target.checked)}
                  disabled={!editingParams}
                  style={{ accentColor: colors.accent }}
                />
              </View>
              <View style={{ flexDirection: "row", alignItems: "center", gap: spacing.sm }}>
                <Text style={styles.paramLabel}>TTL</Text>
                <input
                  type="number"
                  value={paramTtl}
                  onChange={(e) => setParamTtl(e.target.value)}
                  disabled={!editingParams}
                  placeholder="seconds"
                  style={{
                    width: 100,
                    backgroundColor: colors.bgPrimary,
                    color: colors.textPrimary,
                    border: `1px solid ${colors.border}`,
                    borderRadius: radii.sm,
                    padding: "4px 8px",
                    fontFamily: fonts.mono,
                    fontSize: 12,
                  }}
                />
              </View>
            </View>
          </View>
        )}

        {/* Upload DID log */}
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>Upload DID Log</Text>
          <Text style={styles.hint}>
            Paste the JSONL content for the did.jsonl file.
          </Text>
          {didDetail && didDetail.versionCount > 0 && (
            <Pressable
              style={[styles.outlineButton, loadingRaw && styles.disabled]}
              onPress={handleLoadCurrentJsonl}
              disabled={loadingRaw}
            >
              <Text style={styles.outlineButtonText}>
                {loadingRaw ? "Loading..." : "Load Current JSONL"}
              </Text>
            </Pressable>
          )}
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

        {/* Danger Zone */}
        <View style={[styles.card, styles.dangerCard]}>
          <Text style={styles.sectionTitle}>Danger Zone</Text>

          {/* Rollback */}
          <Pressable
            style={[
              styles.warningButton,
              (logEntryCount < 2 || rollingBack) && styles.disabled,
            ]}
            onPress={handleRollback}
            disabled={logEntryCount < 2 || rollingBack}
          >
            <Text style={styles.warningButtonText}>
              {rollingBack ? "Rolling back..." : "Rollback Last Entry"}
            </Text>
          </Pressable>
          {logEntryCount < 2 && logEntryCount > 0 && (
            <Text style={[styles.hint, { marginTop: spacing.xs, marginBottom: spacing.md }]}>
              Cannot rollback — only one log entry exists.
            </Text>
          )}

          {/* Delete */}
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
  wide: {
    maxWidth: 1200,
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
  dangerCard: {
    borderColor: "rgba(255, 92, 92, 0.25)",
  },
  sectionTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  sectionTitleRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: spacing.md,
  },
  sectionActions: {
    flexDirection: "row",
    gap: spacing.sm,
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
  smallButton: {
    borderRadius: radii.sm,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 4,
    paddingHorizontal: spacing.md,
  },
  smallButtonText: {
    fontSize: 12,
    fontFamily: fonts.semibold,
    color: colors.textSecondary,
  },
  outlineButton: {
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.accent,
    paddingVertical: 10,
    alignItems: "center",
    marginBottom: spacing.md,
  },
  outlineButtonText: {
    color: colors.accent,
    fontSize: 13,
    fontFamily: fonts.semibold,
  },
  warningButton: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.warning,
    paddingVertical: 14,
    alignItems: "center",
    marginBottom: spacing.md,
  },
  warningButtonText: {
    color: colors.warning,
    fontSize: 14,
    fontFamily: fonts.semibold,
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
  watcherRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: spacing.sm,
    marginBottom: spacing.md,
  },
  watcherDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    marginTop: 4,
  },
  watcherInfo: {
    flex: 1,
  },
  watcherUrl: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
  },
  watcherMeta: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginTop: 2,
  },
  watcherError: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginTop: 2,
  },
  paramField: {
    marginBottom: spacing.md,
  },
  paramLabel: {
    fontSize: 12,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 1,
    marginBottom: spacing.xs,
  },
});
