import { useEffect, useRef, useState, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  Pressable,
  FlatList,
  ActivityIndicator,
} from "react-native";
import { Link, useLocalSearchParams, useRouter } from "expo-router";
import * as Clipboard from "expo-clipboard";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { showAlert } from "../../lib/alert";
import type { DidRecord } from "../../lib/api";

type PathStatus = null | "checking" | "available" | "taken" | "error";

export default function DidList() {
  const api = useApi();
  const { isAuthenticated, role } = useAuth();
  const router = useRouter();
  const { owner } = useLocalSearchParams<{ owner?: string }>();
  const [dids, setDids] = useState<DidRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [creatingRoot, setCreatingRoot] = useState(false);
  const [copiedDid, setCopiedDid] = useState<string | null>(null);

  // Inline create form state
  const [showForm, setShowForm] = useState(false);
  const [customPath, setCustomPath] = useState("");
  const [pathStatus, setPathStatus] = useState<PathStatus>(null);

  const refresh = useCallback(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    api
      .listDids(owner)
      .then((data) => {
        setDids(data);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated, owner]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const resetForm = () => {
    setShowForm(false);
    setCustomPath("");
    setPathStatus(null);
  };

  // Debounced availability check as user types
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    const trimmed = customPath.trim();
    if (trimmed.length < 2) {
      setPathStatus(null);
      return;
    }

    setPathStatus("checking");
    debounceRef.current = setTimeout(() => {
      api
        .checkName(trimmed)
        .then((result) =>
          setPathStatus(result.available ? "available" : "taken"),
        )
        .catch(() => setPathStatus("error"));
    }, 400);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [customPath, api]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      const path = customPath.trim() || undefined;
      await api.createDid(path);
      resetForm();
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create DID";
      showAlert("Error", msg);
    } finally {
      setCreating(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>Please log in to manage DIDs.</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.buttonPrimary}>
            <Text style={styles.buttonPrimaryText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  const handleCreateRootDid = async () => {
    setCreatingRoot(true);
    try {
      await api.createDid(".well-known");
      refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create root DID";
      showAlert("Error", msg);
    } finally {
      setCreatingRoot(false);
    }
  };

  const showRootDidButton =
    role === "admin" &&
    !dids.some((d) => d.mnemonic === ".well-known") &&
    !loading;

  const handleCopyDid = async (didId: string) => {
    await Clipboard.setStringAsync(didId);
    setCopiedDid(didId);
    setTimeout(() => setCopiedDid(null), 2000);
  };

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
      {owner && (
        <View style={styles.ownerBanner}>
          <Text style={styles.ownerBannerText} numberOfLines={1}>
            DIDs owned by {owner}
          </Text>
          <Pressable
            style={styles.buttonSecondary}
            onPress={() => router.replace("/dids")}
          >
            <Text style={styles.buttonSecondaryText}>Your DIDs</Text>
          </Pressable>
        </View>
      )}

      <View style={styles.header}>
        <Text style={styles.title}>{owner ? "Owner DIDs" : "Your DIDs"}</Text>
        <View style={styles.headerActions}>
          {showRootDidButton && (
            <Pressable
              style={[styles.buttonSecondary, creatingRoot && styles.disabled]}
              onPress={handleCreateRootDid}
              disabled={creatingRoot}
            >
              <Text style={styles.buttonSecondaryText}>
                {creatingRoot ? "Creating..." : "Create Root DID"}
              </Text>
            </Pressable>
          )}
          {!showForm && (
            <Pressable
              style={styles.buttonPrimary}
              onPress={() => setShowForm(true)}
            >
              <Text style={styles.buttonPrimaryText}>+ New DID</Text>
            </Pressable>
          )}
        </View>
      </View>

      {showForm && (
        <View style={styles.formCard}>
          <TextInput
            style={styles.input}
            placeholder="custom-name or path/to/name (optional)"
            placeholderTextColor={colors.textTertiary}
            value={customPath}
            onChangeText={setCustomPath}
            autoCapitalize="none"
            autoCorrect={false}
          />
          <Text style={styles.validationHint}>
            Segments: 2–63 chars, lowercase letters, digits, and hyphens.
            {"\n"}Use / for folders (e.g. people/staff/glenn).
            {"\n"}Leave blank for a random mnemonic.
          </Text>

          {pathStatus === "checking" && (
            <Text style={styles.statusChecking}>Checking availability...</Text>
          )}
          {pathStatus === "available" && (
            <Text style={styles.statusAvailable}>Available</Text>
          )}
          {pathStatus === "taken" && (
            <Text style={styles.statusTaken}>Already taken</Text>
          )}
          {pathStatus === "error" && (
            <Text style={styles.statusTaken}>
              Could not check availability
            </Text>
          )}

          <View style={styles.formActions}>
            <Pressable
              style={[styles.buttonPrimary, creating && styles.disabled]}
              onPress={handleCreate}
              disabled={creating}
            >
              <Text style={styles.buttonPrimaryText}>
                {creating ? "Creating..." : "Create"}
              </Text>
            </Pressable>
            <Pressable
              style={styles.buttonSecondary}
              onPress={resetForm}
              disabled={creating}
            >
              <Text style={styles.buttonSecondaryText}>Cancel</Text>
            </Pressable>
          </View>
        </View>
      )}

      {error && <Text style={styles.errorText}>{error}</Text>}

      {loading ? (
        <ActivityIndicator
          color={colors.accent}
          size="large"
          style={{ marginTop: spacing.xxl }}
        />
      ) : dids.length === 0 ? (
        <Text style={styles.hint}>
          No DIDs yet. Create one to get started.
        </Text>
      ) : (
        <FlatList
          data={dids}
          keyExtractor={(item) => item.mnemonic}
          contentContainerStyle={{ gap: spacing.md }}
          renderItem={({ item }) => (
            <Link href={`/dids/${item.mnemonic}`} asChild>
              <Pressable style={styles.card}>
                <Text style={styles.mnemonic}>{item.mnemonic}</Text>
                {item.versionCount === 0 ? (
                  <Text style={styles.statusPending}>Pending upload</Text>
                ) : (
                  <View style={styles.didIdRow}>
                    <Text style={styles.statusActive} numberOfLines={1}>
                      {item.didId ?? "Uploaded"}
                    </Text>
                    {item.didId && (
                      <Pressable
                        style={styles.copyButton}
                        onPress={(e) => {
                          e.preventDefault();
                          handleCopyDid(item.didId!);
                        }}
                      >
                        <Text style={styles.copyButtonText}>
                          {copiedDid === item.didId ? "Copied!" : "Copy"}
                        </Text>
                      </Pressable>
                    )}
                  </View>
                )}
                <View style={styles.meta}>
                  <Text style={styles.metaText}>
                    Versions: {item.versionCount.toLocaleString()}
                  </Text>
                  <Text style={styles.metaText}>
                    Updated: {formatDate(item.updatedAt)}
                  </Text>
                  <View style={{ flex: 1 }} />
                  <Text style={styles.resolveCount}>
                    {item.totalResolves.toLocaleString()} resolves
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
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
  },
  containerCenter: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    alignItems: "center",
    justifyContent: "center",
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: spacing.xl,
    flexWrap: "wrap",
    gap: spacing.md,
  },
  headerActions: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
  },
  title: {
    fontSize: 22,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
  },
  formCard: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    marginBottom: spacing.xl,
    gap: spacing.sm,
  },
  input: {
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 10,
    paddingHorizontal: spacing.md,
    color: colors.textPrimary,
    fontFamily: fonts.mono,
    fontSize: 14,
  },
  validationHint: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  statusChecking: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  statusAvailable: {
    fontSize: 13,
    fontFamily: fonts.semibold,
    color: colors.success,
  },
  statusTaken: {
    fontSize: 13,
    fontFamily: fonts.semibold,
    color: colors.error,
  },
  formActions: {
    flexDirection: "row",
    gap: spacing.md,
    marginTop: spacing.sm,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
  },
  mnemonic: {
    fontSize: 16,
    fontFamily: fonts.mono,
    fontWeight: "600",
    color: colors.accent,
    marginBottom: spacing.sm,
  },
  statusPending: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.warning,
    marginBottom: spacing.sm,
  },
  didIdRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    marginBottom: spacing.sm,
  },
  statusActive: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.success,
    flexShrink: 1,
  },
  copyButton: {
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.sm,
    paddingVertical: 2,
    paddingHorizontal: spacing.sm,
  },
  copyButtonText: {
    fontSize: 11,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
  },
  meta: {
    flexDirection: "row",
    gap: spacing.lg,
    alignItems: "center",
  },
  metaText: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  resolveCount: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
  },
  ownerBanner: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.md,
    marginBottom: spacing.lg,
    gap: spacing.md,
  },
  ownerBannerText: {
    flex: 1,
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textSecondary,
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginTop: spacing.xxl,
    marginBottom: spacing.lg,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
    marginBottom: spacing.md,
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 12,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
  },
  buttonSecondary: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 12,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
  },
  disabled: {
    opacity: 0.5,
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
  buttonSecondaryText: {
    color: colors.textSecondary,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
});
