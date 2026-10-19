import { useEffect, useRef, useState, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  Pressable,
  FlatList,
  ScrollView,
  ActivityIndicator,
} from "react-native";
import { Link, useLocalSearchParams, useRouter } from "expo-router";
import * as Clipboard from "expo-clipboard";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { useDomains } from "../../components/DomainProvider";
import {
  AgentNameChips,
  servedNames,
} from "../../components/AgentNameChips";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { showAlert } from "../../lib/alert";
import type { DidRecord } from "../../lib/api";
import { matchesDomain } from "../../lib/domain";
import { DidQrButton } from "../../components/DidQrButton";
import { TableRow } from "../../components/TableRow";
import {
  matchesSearch,
  nextSort,
  sortDids,
  truncateDid,
  type DidSort,
  type DidSortKey,
} from "../../lib/did-table";

/** The table's columns: header, sort key, and fixed width (`flex` for the
 *  two that take the remaining space). */
const COLUMNS: {
  key: DidSortKey;
  label: string;
  width?: number;
  flex?: number;
  align?: "right";
}[] = [
  { key: "mnemonic", label: "Name", flex: 2 },
  { key: "didId", label: "DID", flex: 3 },
  { key: "versions", label: "Versions", width: 84, align: "right" },
  { key: "created", label: "Created", width: 150 },
  { key: "updated", label: "Updated", width: 150 },
  { key: "resolves", label: "Resolves", width: 100, align: "right" },
];

/** Below this the table scrolls sideways rather than squeezing the DID. */
const TABLE_MIN_WIDTH = 980;

type PathStatus = null | "checking" | "available" | "taken" | "error";

export default function DidList() {
  const api = useApi();
  const { isAuthenticated, role, did: myDid } = useAuth();
  const router = useRouter();
  const { owner } = useLocalSearchParams<{ owner?: string }>();
  const {
    domains,
    currentDomain,
    defaultDomain,
    loaded: domainsLoaded,
  } = useDomains();
  const [dids, setDids] = useState<DidRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [creatingRoot, setCreatingRoot] = useState(false);
  const [copiedDid, setCopiedDid] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<DidSort>({ key: "mnemonic", dir: "asc" });

  // Inline create form state
  const [showForm, setShowForm] = useState(false);
  const [customPath, setCustomPath] = useState("");
  const [pathStatus, setPathStatus] = useState<PathStatus>(null);
  // T26: optional domain override on create. Default to the
  // switcher's current selection so admins managing one specific
  // domain don't have to re-pick on every create.
  const [createDomain, setCreateDomain] = useState<string | null>(
    currentDomain ?? defaultDomain ?? null,
  );

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
        .checkName(trimmed, createDomain ?? undefined)
        .then((result) =>
          setPathStatus(result.available ? "available" : "taken"),
        )
        .catch(() => setPathStatus("error"));
    }, 400);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [customPath, api, createDomain]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      const path = customPath.trim() || undefined;
      await api.createDid(path, createDomain ?? undefined);
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

  // Filter the list to the current domain when the switcher has one
  // pinned. "All domains" (currentDomain === null, admin-only) shows
  // everything.
  //
  // For records that still carry an empty `domain` (legacy slots
  // pre-M-01, plus the historical bug where the REST `request_uri`
  // handler dropped the `domain` field on create), fall back to the
  // host segment of the DID itself: `did:webvh:scid:HOST(:path…)` and
  // `did:web:HOST(:path…)`. Without this fallback the switcher looks
  // broken in the brief window between an operator upgrading to the
  // fix and publish-time backfill tagging each slot. See
  // `lib/domain.ts` for the shared matchesDomain / extractDidHost
  // implementation — both this view and the dashboard's per-domain
  // stat cards consume the same helpers.
  const hiddenNoDomainCount =
    currentDomain === null
      ? 0
      : dids.filter((d) => !d.domain && !matchesDomain(d, currentDomain))
          .length;
  const visibleDids =
    currentDomain === null
      ? dids
      : dids.filter((d) => matchesDomain(d, currentDomain));
  const rows = sortDids(
    visibleDids.filter((d) => matchesSearch(d, search)),
    sort,
  );
  const showOwnerInfo = role === "admin" && !owner;

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
        <View style={{ flex: 1 }}>
          <Text style={styles.title}>
            {owner ? "Owner DIDs" : role === "admin" ? "All DIDs" : "Your DIDs"}
          </Text>
          {currentDomain !== null && (
            <Text style={styles.filterCaption}>
              Filtered to {currentDomain}
              {hiddenNoDomainCount > 0
                ? ` · ${hiddenNoDomainCount} unassigned DID${
                    hiddenNoDomainCount === 1 ? "" : "s"
                  } hidden`
                : ""}
            </Text>
          )}
        </View>
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
            accessibilityLabel="DID path or mnemonic"
          />
          <Text style={styles.validationHint}>
            Segments: 2–63 chars, lowercase letters, digits, and hyphens.
            {"\n"}Use / for folders (e.g. people/staff/glenn).
            {"\n"}Leave blank for a random mnemonic.
          </Text>

          {domainsLoaded && domains.length > 0 && (
            <View style={styles.domainPickerWrap}>
              <Text style={styles.formLabel}>Host on domain</Text>
              <View style={styles.domainPickerRow}>
                {domains.map((d) => (
                  <Pressable
                    key={d.name}
                    accessibilityRole="button"
                    accessibilityState={{ selected: createDomain === d.name }}
                    onPress={() => setCreateDomain(d.name)}
                    disabled={d.status === "disabled"}
                    style={[
                      styles.domainPickerOption,
                      createDomain === d.name && styles.domainPickerOptionActive,
                      d.status === "disabled" && styles.disabled,
                    ]}
                  >
                    <Text
                      style={[
                        styles.domainPickerOptionText,
                        createDomain === d.name && styles.domainPickerOptionTextActive,
                      ]}
                    >
                      {d.name}
                      {defaultDomain === d.name ? " · default" : ""}
                    </Text>
                  </Pressable>
                ))}
              </View>
              <Text style={styles.validationHint}>
                The selected domain becomes the DID's host. Omit (rare) to let the
                daemon pick your ACL default.
              </Text>
            </View>
          )}

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
      ) : visibleDids.length === 0 ? (
        <Text style={styles.hint}>
          {currentDomain
            ? `No DIDs on ${currentDomain} yet. Create one to get started, or pick a different domain from the switcher.`
            : "No DIDs yet. Create one to get started."}
        </Text>
      ) : (
        <>
          <View style={styles.searchRow}>
            <TextInput
              style={styles.searchInput}
              placeholder="Search by name, DID, method or domain"
              placeholderTextColor={colors.textTertiary}
              value={search}
              onChangeText={setSearch}
              autoCapitalize="none"
              autoCorrect={false}
              accessibilityLabel="Search DIDs"
            />
            <Text style={styles.countText}>
              {rows.length === visibleDids.length
                ? `${visibleDids.length.toLocaleString()} DID${visibleDids.length === 1 ? "" : "s"}`
                : `${rows.length.toLocaleString()} of ${visibleDids.length.toLocaleString()}`}
            </Text>
          </View>
          <ScrollView horizontal contentContainerStyle={styles.tableScroll}>
            <View style={styles.table}>
              <View style={styles.headRow} accessibilityRole="header">
                {COLUMNS.map((c) => {
                  const active = sort.key === c.key;
                  return (
                    <Pressable
                      key={c.key}
                      accessibilityRole="button"
                      accessibilityLabel={`Sort by ${c.label}`}
                      onPress={() => setSort(nextSort(sort, c.key))}
                      style={[
                        styles.cell,
                        c.flex ? { flex: c.flex } : { width: c.width },
                        c.align === "right" && styles.cellRight,
                      ]}
                    >
                      <Text
                        style={[styles.headText, active && styles.headTextActive]}
                        numberOfLines={1}
                      >
                        {c.label}
                        {active ? (sort.dir === "asc" ? " ▲" : " ▼") : ""}
                      </Text>
                    </Pressable>
                  );
                })}
              </View>
              {rows.length === 0 ? (
                <Text style={styles.hint}>No DIDs match “{search.trim()}”.</Text>
              ) : (
                <FlatList
                  data={rows}
                  keyExtractor={(item) => item.mnemonic}
                  renderItem={({ item, index }) => {
                    const isOwn = item.owner === myDid;
                    const names = servedNames(item.agentNames);
                    return (
                      <Link href={`/dids/${item.mnemonic}`} asChild>
                        <TableRow
                          hoverStyle={styles.rowHover}
                          style={[
                            styles.row,
                            index % 2 === 1 && styles.rowAlt,
                            showOwnerInfo &&
                              (isOwn ? styles.rowOwn : styles.rowOther),
                          ]}
                        >
                          <View style={[styles.cell, { flex: 2 }]}>
                            <View style={styles.nameRow}>
                              <Text style={styles.mnemonic} numberOfLines={1}>
                                {item.mnemonic}
                              </Text>
                              {item.method && (
                                <View style={styles.methodBadge}>
                                  <Text style={styles.methodBadgeText}>
                                    did:{item.method}
                                  </Text>
                                </View>
                              )}
                              {showOwnerInfo && isOwn && (
                                <View style={styles.youBadge}>
                                  <Text style={styles.youBadgeText}>You</Text>
                                </View>
                              )}
                              {item.disabled && (
                                <View style={styles.disabledBadge}>
                                  <Text style={styles.disabledBadgeText}>Suspended</Text>
                                </View>
                              )}
                            </View>
                            {currentDomain === null && item.domain && (
                              <Text style={styles.subText} numberOfLines={1}>
                                {item.domain}
                              </Text>
                            )}
                            {/* Served agent names, under the name: an alias
                                for the DID, as on the detail page. */}
                            {names.length > 0 && (
                              <View style={styles.agentNamesRow}>
                                <AgentNameChips
                                  names={names}
                                  domain={item.domain}
                                  didId={item.didId}
                                  size="sm"
                                />
                              </View>
                            )}
                            {showOwnerInfo && !isOwn && (
                              <Text style={styles.subText} numberOfLines={1}>
                                Owner: {item.owner}
                              </Text>
                            )}
                          </View>
                          <View style={[styles.cell, { flex: 3 }]}>
                            {item.versionCount === 0 ? (
                              <Text style={styles.statusPending}>Pending upload</Text>
                            ) : item.didId ? (
                              <View style={styles.didIdRow}>
                                <Text
                                  style={styles.didText}
                                  numberOfLines={1}
                                  accessibilityLabel={item.didId}
                                  // Full DID on hover (web).
                                  {...({ title: item.didId } as any)}
                                >
                                  {truncateDid(item.didId)}
                                </Text>
                                <Pressable
                                  accessibilityRole="button"
                                  accessibilityLabel="Copy DID"
                                  style={styles.copyButton}
                                  onPress={(e: any) => {
                                    e?.preventDefault?.();
                                    e?.stopPropagation?.();
                                    handleCopyDid(item.didId!);
                                  }}
                                >
                                  <Text style={styles.copyButtonText}>
                                    {copiedDid === item.didId ? "Copied!" : "Copy"}
                                  </Text>
                                </Pressable>
                                <DidQrButton did={item.didId} label={item.mnemonic} />
                              </View>
                            ) : (
                              <Text style={styles.subText}>Uploaded</Text>
                            )}
                          </View>
                          <View style={[styles.cell, styles.cellRight, { width: 84 }]}>
                            <Text style={styles.numText}>
                              {item.versionCount.toLocaleString()}
                            </Text>
                          </View>
                          <View style={[styles.cell, { width: 150 }]}>
                            <Text style={styles.dateText}>{formatDate(item.createdAt)}</Text>
                          </View>
                          <View style={[styles.cell, { width: 150 }]}>
                            <Text style={styles.dateText}>{formatDate(item.updatedAt)}</Text>
                          </View>
                          <View style={[styles.cell, styles.cellRight, { width: 100 }]}>
                            <Text style={styles.numText}>
                              {item.totalResolves.toLocaleString()}
                            </Text>
                          </View>
                        </TableRow>
                      </Link>
                    );
                  }}
                />
              )}
            </View>
          </ScrollView>
        </>
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
  searchRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    marginBottom: spacing.md,
  },
  searchInput: {
    flex: 1,
    maxWidth: 520,
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 8,
    paddingHorizontal: spacing.md,
    color: colors.textPrimary,
    fontFamily: fonts.regular,
    fontSize: 14,
  },
  countText: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
  },
  tableScroll: {
    flexGrow: 1,
  },
  table: {
    flex: 1,
    minWidth: TABLE_MIN_WIDTH,
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    overflow: "hidden",
  },
  headRow: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: colors.bgHeader,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    paddingHorizontal: spacing.sm,
  },
  headText: {
    fontSize: 11,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.6,
  },
  headTextActive: {
    color: colors.textPrimary,
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    borderLeftWidth: 3,
    borderLeftColor: "transparent",
  },
  rowAlt: {
    backgroundColor: "rgba(255, 255, 255, 0.015)",
  },
  rowHover: {
    backgroundColor: colors.bgTertiary,
  },
  rowOwn: {
    borderLeftColor: colors.teal,
  },
  rowOther: {
    borderLeftColor: colors.textTertiary,
  },
  cell: {
    paddingVertical: 10,
    paddingHorizontal: spacing.sm,
    justifyContent: "center",
    minWidth: 0,
  },
  cellRight: {
    alignItems: "flex-end",
  },
  nameRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.xs,
    flexWrap: "wrap",
  },
  subText: {
    marginTop: 2,
    fontSize: 11,
    fontFamily: fonts.mono,
    color: colors.textTertiary,
  },
  didText: {
    fontSize: 12,
    fontFamily: fonts.mono,
    color: colors.success,
    flexShrink: 1,
  },
  numText: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textPrimary,
    fontVariant: ["tabular-nums"],
  },
  dateText: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  disabledBadge: {
    backgroundColor: colors.errorBg,
    borderRadius: radii.sm,
    paddingVertical: 2,
    paddingHorizontal: spacing.sm,
  },
  disabledBadgeText: {
    fontSize: 10,
    fontFamily: fonts.semibold,
    color: colors.error,
  },
  youBadge: {
    backgroundColor: colors.tealMuted,
    borderRadius: radii.sm,
    paddingVertical: 2,
    paddingHorizontal: spacing.sm,
  },
  youBadgeText: {
    fontSize: 11,
    fontFamily: fonts.semibold,
    color: colors.teal,
  },
  mnemonic: {
    fontSize: 14,
    fontFamily: fonts.mono,
    fontWeight: "600",
    color: colors.accent,
  },
  statusPending: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.warning,
  },
  didIdRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.xs,
  },
  agentNamesRow: {
    marginTop: 4,
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
  filterCaption: {
    marginTop: 4,
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
  },
  formLabel: {
    fontFamily: fonts.semibold,
    fontSize: 12,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.6,
    marginTop: spacing.sm,
  },
  domainPickerWrap: {
    marginTop: spacing.sm,
    gap: spacing.xs,
  },
  domainPickerRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.xs,
    marginTop: 4,
  },
  domainPickerOption: {
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
    borderRadius: radii.full,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.bgTertiary,
  },
  domainPickerOptionActive: {
    borderColor: colors.accent,
    backgroundColor: colors.accent,
  },
  domainPickerOptionText: {
    fontFamily: fonts.medium,
    fontSize: 12,
    color: colors.textSecondary,
  },
  domainPickerOptionTextActive: {
    color: colors.textOnAccent,
  },
  methodBadge: {
    backgroundColor: colors.tealMuted,
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
    borderRadius: radii.sm,
  },
  methodBadgeText: {
    fontFamily: fonts.semibold,
    fontSize: 10,
    color: colors.teal,
    letterSpacing: 0.4,
  },
});
