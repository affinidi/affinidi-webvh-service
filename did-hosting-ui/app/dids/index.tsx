import { useEffect, useRef, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  ScrollView,
  ActivityIndicator,
  useWindowDimensions,
} from "react-native";
import { Link, useLocalSearchParams, useRouter } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { useDomains } from "../../components/DomainProvider";
import { AgentNameChips, servedNames } from "../../components/AgentNameChips";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { Field } from "../../components/Field";
import { Heading } from "../../components/Heading";
import { RequireAuth } from "../../components/RequireAuth";
import { SegmentedControl } from "../../components/SegmentedControl";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { webAria } from "../../lib/a11y";
import { confirm, notify } from "../../lib/feedback";
import { didPathError } from "../../lib/validation";
import { ErrorWithRetry } from "../../components/QueryState";
import { DidCards } from "../../components/DidCards";
import { errorMessage } from "../../lib/errors";
import { plural } from "../../lib/plural";
import { invalidateQueries, useTrustTaskQuery } from "../../lib/query";
import { formatDate } from "../../lib/time";
import { matchesDomain } from "../../lib/domain";
import { DidQrButton } from "../../components/DidQrButton";
import { TableRow } from "../../components/TableRow";
import {
  matchesSearch,
  nextSort,
  sortDids,
  compactDid,
  didTextWidth,
  nameColumnWidth,
  type DidSort,
  type DidSortKey,
} from "../../lib/did-table";

/** Copy and QR, with the gaps around them. */
const DID_ACTIONS_WIDTH = 104;

/** The table's columns: header, sort key, and width. The name and DID
 *  widths come from the listed DIDs (`nameColumnWidth`, `didTextWidth`);
 *  the rest are fixed. The name column is exactly its width; the others
 *  share any spare width equally, so a wide window doesn't strand it in
 *  one column. */
const COLUMNS: {
  key: DidSortKey;
  label: string;
  width?: number;
  align?: "right";
  /** Extra room after a right-aligned number, before the dates. */
  gapAfter?: boolean;
}[] = [
  { key: "mnemonic", label: "Name" },
  { key: "didId", label: "DID" },
  { key: "versions", label: "Versions", width: 100, align: "right", gapAfter: true },
  { key: "created", label: "Created", width: 150 },
  { key: "updated", label: "Updated", width: 150 },
  { key: "resolves", label: "Resolves", width: 100, align: "right" },
];

type PathStatus = null | "checking" | "available" | "taken" | "error";

/** Every list of DIDs is read under this prefix; a write that changes one
 *  invalidates them all. */
const DIDS_KEY = ["dids"] as const;

export default function DidList() {
  return (
    <RequireAuth purpose="manage DIDs">
      <DidListBody />
    </RequireAuth>
  );
}

function DidListBody() {
  const api = useApi();
  const { role, did: myDid } = useAuth();
  const router = useRouter();
  const { owner } = useLocalSearchParams<{ owner?: string }>();
  const { domains, currentDomain, defaultDomain, loaded: domainsLoaded } = useDomains();
  const {
    data,
    loading,
    error: loadError,
    refetch,
  } = useTrustTaskQuery([...DIDS_KEY, "list", owner ?? null], () => api.listDids(owner));
  const dids = data ?? [];
  const { width } = useWindowDimensions();
  // Under this width the table would scroll sideways; rows become cards.
  const narrow = width > 0 && width < 700;
  const refresh = () => void invalidateQueries([...DIDS_KEY]);
  const [creating, setCreating] = useState(false);

  const [creatingRoot, setCreatingRoot] = useState(false);
  // Accepting a DID another owner offered to this identity.
  const [showAccept, setShowAccept] = useState(false);
  const [acceptPath, setAcceptPath] = useState("");
  const [accepting, setAccepting] = useState(false);
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

  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const resetForm = () => {
    setShowForm(false);
    setCustomPath("");
    setPathStatus(null);
  };

  // Checked here first with the server's own path grammar, so a path the
  // server would refuse is said at once and never sent.
  const pathError = didPathError(customPath.trim());
  const trimmedPath = customPath.trim();
  // An empty path asks for a random name; anything else must be free.
  const canCreate = !creating && !pathError && (trimmedPath === "" || pathStatus === "available");

  // Debounced availability check as user types
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    const trimmed = customPath.trim();
    if (trimmed.length < 2 || didPathError(trimmed)) {
      setPathStatus(null);
      return;
    }

    setPathStatus("checking");
    debounceRef.current = setTimeout(() => {
      api
        .checkName(trimmed, createDomain ?? undefined)
        .then((result) => setPathStatus(result.available ? "available" : "taken"))
        .catch(() => setPathStatus("error"));
    }, 400);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [customPath, api, createDomain]);

  const handleCreate = async () => {
    if (!canCreate) return;
    setCreating(true);
    try {
      const path = customPath.trim() || undefined;
      const created = await api.createDid(path, createDomain ?? undefined);
      resetForm();
      refresh();
      notify(
        "success",
        `Reserved “${created.mnemonic}”`,
        `Next: have the DID's agent sign its first did.jsonl and publish it here${created.didUrl ? ` (${created.didUrl})` : ""} — or open the DID and upload the file. Until then it shows as “Pending upload”.`,
      );
    } catch (e: unknown) {
      notify("error", "Could not create the DID", errorMessage(e, "Failed to create DID"));
    } finally {
      setCreating(false);
    }
  };

  const handleAccept = async () => {
    const path = acceptPath.trim();
    if (!path || !myDid || accepting) return;
    setAccepting(true);
    try {
      await api.acceptDidTransfer(path, myDid);
      setAcceptPath("");
      setShowAccept(false);
      refresh();
      notify("success", "DID accepted", `"${path}" is now yours.`);
    } catch (e: unknown) {
      notify("error", "Could not accept the DID", errorMessage(e, "Failed to accept the DID"));
    } finally {
      setAccepting(false);
    }
  };

  // The root DID belongs to one domain: the one the switcher is on, else the
  // default.
  const rootDomain = currentDomain ?? defaultDomain ?? null;
  const handleCreateRootDid = async () => {
    if (!rootDomain) return;
    const ok = await confirm({
      title: `Reserve the root DID for ${rootDomain}?`,
      body:
        `The root DID stands for the domain itself: it resolves at ` +
        `https://${rootDomain}/.well-known/did.jsonl, and it is the only DID that can hold ` +
        `the community name ${rootDomain}/@. This reserves the slot; its agent then ` +
        `publishes the signed did.jsonl, as for any other DID.`,
      confirmLabel: "Reserve root DID",
      destructive: false,
    });
    if (!ok) return;
    setCreatingRoot(true);
    try {
      await api.createDid(".well-known", rootDomain);
      refresh();
      notify(
        "success",
        `Root DID reserved for ${rootDomain}`,
        "Next: have its agent publish the signed did.jsonl, or open it and upload the file.",
      );
    } catch (e: unknown) {
      notify(
        "error",
        "Could not create the root DID",
        errorMessage(e, "Failed to create root DID"),
      );
    } finally {
      setCreatingRoot(false);
    }
  };

  const showRootDidButton =
    role === "admin" &&
    !!rootDomain &&
    !loading &&
    !loadError &&
    !dids.some((d) => d.mnemonic === ".well-known" && matchesDomain(d, rootDomain));

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
      : dids.filter((d) => !d.domain && !matchesDomain(d, currentDomain)).length;
  const visibleDids =
    currentDomain === null ? dids : dids.filter((d) => matchesDomain(d, currentDomain));
  const rows = sortDids(
    visibleDids.filter((d) => matchesSearch(d, search)),
    sort,
  );
  const showOwnerInfo = role === "admin" && !owner;
  // A badge on every row says nothing. Show the method only when the list
  // mixes methods (otherwise the DID's own prefix says it), and mark owners
  // only when the list mixes them.
  const showMethod = new Set(visibleDids.map((d) => d.method ?? "")).size > 1;
  const markOwners = showOwnerInfo && visibleDids.some((d) => d.owner !== myDid);
  // Sized from the domain's DIDs, not the search results, so the columns
  // hold still while typing.
  const nameWidth = nameColumnWidth(
    visibleDids.map((d) => ({
      name: d.mnemonic,
      badges: [
        ...(showMethod && d.method ? [`did:${d.method}`] : []),
        ...(markOwners && d.owner === myDid ? ["You"] : []),
        ...(d.disabled ? ["Suspended"] : []),
      ],
      chips: servedNames(d.agentNames).map((n) => `@${n}`),
    })),
  );
  const didWidth = didTextWidth(visibleDids.map((d) => d.didId));
  const columnWidth = (key: DidSortKey, fixed?: number) =>
    key === "mnemonic" ? nameWidth : key === "didId" ? didWidth + DID_ACTIONS_WIDTH : fixed!;
  /** A column's width. The name fits its longest name; the others are
   *  minimums that share any spare width equally. */
  const columnStyle = (key: DidSortKey, fixed?: number) => ({
    flexGrow: key === "mnemonic" ? 0 : 1,
    flexShrink: 0,
    flexBasis: columnWidth(key, fixed),
  });
  // Below the columns' sum the table scrolls sideways instead of squeezing.
  const tableMinWidth =
    COLUMNS.reduce((w, c) => w + columnWidth(c.key, c.width), 0) + 2 * spacing.sm + 3;

  return (
    <View style={styles.container}>
      {owner && (
        <View style={styles.ownerBanner}>
          <Text style={styles.ownerBannerText} numberOfLines={1}>
            DIDs owned by {owner}
          </Text>
          <Button label="Your DIDs" variant="secondary" onPress={() => router.replace("/dids")} />
        </View>
      )}

      <View style={styles.header}>
        <View style={{ flex: 1 }}>
          <Heading style={styles.title}>
            {owner ? "Owner DIDs" : role === "admin" ? "All DIDs" : "Your DIDs"}
          </Heading>
          {currentDomain !== null && (
            <Text style={styles.filterCaption}>
              Filtered to {currentDomain}
              {hiddenNoDomainCount > 0
                ? ` · ${plural(hiddenNoDomainCount, "unassigned DID", "unassigned DIDs")} hidden`
                : ""}
            </Text>
          )}
        </View>
        <View style={styles.headerActions}>
          {showRootDidButton && (
            <Button
              label={`Create root DID for ${rootDomain}`}
              variant="secondary"
              busy={creatingRoot}
              busyLabel="Creating..."
              onPress={handleCreateRootDid}
            />
          )}
          {!showAccept && myDid && (
            <Button label="Accept a DID" variant="secondary" onPress={() => setShowAccept(true)} />
          )}
          {!showForm && <Button label="+ New DID" onPress={() => setShowForm(true)} />}
        </View>
      </View>

      {showAccept && (
        <View style={styles.formCard}>
          <Field
            label="Path of the DID offered to you"
            hideLabel
            inputStyle={styles.input}
            placeholder="path of the DID offered to you"
            value={acceptPath}
            onChangeText={setAcceptPath}
            onSubmit={handleAccept}
            autoCapitalize="none"
            autoCorrect={false}
            style={styles.fieldTight}
          />
          <Text style={styles.validationHint}>
            Another owner offered you a DID. Enter its path to take ownership; the offer lapses
            after 72 hours.
          </Text>
          <View style={styles.formActions}>
            <Button
              label="Accept"
              busy={accepting}
              busyLabel="Accepting..."
              disabled={!acceptPath.trim()}
              onPress={handleAccept}
            />
            <Button
              label="Cancel"
              variant="secondary"
              disabled={accepting}
              onPress={() => {
                setShowAccept(false);
                setAcceptPath("");
              }}
            />
          </View>
        </View>
      )}

      {showForm && (
        <View style={styles.formCard}>
          <Field
            label="DID path (optional)"
            hideLabel
            inputStyle={styles.input}
            placeholder="custom-name or path/to/name (optional)"
            value={customPath}
            onChangeText={setCustomPath}
            onSubmit={handleCreate}
            error={trimmedPath ? pathError : null}
            autoCapitalize="none"
            autoCorrect={false}
            style={styles.fieldTight}
          />
          <Text style={styles.validationHint}>
            Segments: 2–63 chars, lowercase letters, digits, and hyphens.
            {"\n"}Use / for folders (e.g. people/staff/glenn).
            {"\n"}Leave blank for a random name.
          </Text>

          {domainsLoaded && domains.length > 0 && (
            <View style={styles.domainPickerWrap}>
              <Text style={styles.formLabel}>Host on domain</Text>
              <SegmentedControl
                label="Host on domain"
                value={createDomain}
                onChange={setCreateDomain}
                options={domains.map((d) => ({
                  value: d.name,
                  label: `${d.name}${defaultDomain === d.name ? " · default" : ""}`,
                  disabled: d.status === "disabled",
                }))}
                style={styles.domainPickerRow}
              />
              <Text style={styles.validationHint}>
                The selected domain becomes the DID&apos;s host. With none selected, the control
                plane uses your default domain.
              </Text>
            </View>
          )}

          <View aria-live="polite">
            {pathStatus === "checking" && (
              <Text style={styles.statusChecking}>Checking availability...</Text>
            )}
            {pathStatus === "available" && <Text style={styles.statusAvailable}>✓ Available</Text>}
            {pathStatus === "taken" && <Text style={styles.statusTaken}>✗ Already taken</Text>}
            {pathStatus === "error" && (
              <Text style={styles.statusTaken}>Could not check availability</Text>
            )}
          </View>

          <View style={styles.formActions}>
            <Button
              label="Create"
              busy={creating}
              busyLabel="Creating..."
              disabled={!canCreate}
              onPress={handleCreate}
            />
            <Button label="Cancel" variant="secondary" disabled={creating} onPress={resetForm} />
          </View>
        </View>
      )}

      {loadError != null && !data ? (
        <ErrorWithRetry error={loadError} what="the DIDs" onRetry={() => void refetch()} />
      ) : loading ? (
        <ActivityIndicator
          color={colors.accent}
          size="large"
          aria-label="Loading DIDs"
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
            <Field
              label="Search DIDs"
              hideLabel
              style={styles.searchField}
              inputStyle={styles.searchInput}
              placeholder="Search by name, DID, method or domain"
              value={search}
              onChangeText={setSearch}
              autoCapitalize="none"
              autoCorrect={false}
            />
            <Text style={styles.countText} aria-live="polite">
              {rows.length === visibleDids.length
                ? plural(visibleDids.length, "DID", "DIDs")
                : `${rows.length.toLocaleString()} of ${visibleDids.length.toLocaleString()}`}
            </Text>
          </View>
          {narrow ? (
            <DidCards
              rows={rows}
              search={search}
              myDid={myDid}
              markOwners={markOwners}
              showMethod={showMethod}
              showDomain={currentDomain === null}
            />
          ) : (
            <ScrollView horizontal contentContainerStyle={styles.tableScroll}>
              <View
                role="table"
                aria-label="DIDs"
                style={[styles.table, { minWidth: tableMinWidth }]}
              >
                <View style={styles.headRow} role="row">
                  {COLUMNS.map((c) => {
                    const active = sort.key === c.key;
                    return (
                      <View
                        key={c.key}
                        role="columnheader"
                        {...webAria({
                          sort: active ? (sort.dir === "asc" ? "ascending" : "descending") : "none",
                        })}
                        style={[
                          styles.cell,
                          columnStyle(c.key, c.width),
                          c.align === "right" && styles.cellRight,
                          c.gapAfter && styles.cellGapAfter,
                        ]}
                      >
                        <Button
                          variant="ghost"
                          size="sm"
                          accessibilityLabel={`Sort by ${c.label}`}
                          onPress={() => setSort(nextSort(sort, c.key))}
                          style={styles.headButton}
                        >
                          <Text
                            style={[styles.headText, active && styles.headTextActive]}
                            numberOfLines={1}
                          >
                            {c.label}
                            {active ? (sort.dir === "asc" ? " ▲" : " ▼") : ""}
                          </Text>
                        </Button>
                      </View>
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
                      // The row is not itself a link: the name is, and the copy
                      // and QR buttons sit beside it rather than inside it.
                      return (
                        <TableRow
                          hoverStyle={styles.rowHover}
                          style={[
                            styles.row,
                            index % 2 === 1 && styles.rowAlt,
                            markOwners && (isOwn ? styles.rowOwn : styles.rowOther),
                          ]}
                        >
                          <View role="cell" style={[styles.cell, columnStyle("mnemonic")]}>
                            <View style={styles.nameRow}>
                              <Link href={`/dids/${item.mnemonic}`} style={styles.mnemonic}>
                                {item.mnemonic}
                              </Link>
                              {showMethod && item.method && (
                                <View style={styles.methodBadge}>
                                  <Text style={styles.methodBadgeText}>did:{item.method}</Text>
                                </View>
                              )}
                              {markOwners && isOwn && (
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
                                  showHost={false}
                                />
                              </View>
                            )}
                            {markOwners && !isOwn && (
                              <Text style={styles.subText} numberOfLines={1}>
                                Owner: {item.owner}
                              </Text>
                            )}
                          </View>
                          <View role="cell" style={[styles.cell, columnStyle("didId")]}>
                            {item.versionCount === 0 ? (
                              <Text
                                style={styles.statusPending}
                                {...titleAttr("Reserved — waiting for its first signed did.jsonl")}
                              >
                                Pending upload
                              </Text>
                            ) : item.didId ? (
                              <View style={styles.didIdRow}>
                                <Text
                                  style={[styles.didText, { width: didWidth }]}
                                  numberOfLines={1}
                                  aria-label={item.didId}
                                  // Full DID on hover (web).
                                  {...titleAttr(item.didId)}
                                >
                                  {compactDid(item.didId)}
                                </Text>
                                <CopyButton
                                  value={item.didId}
                                  accessibilityLabel={`Copy DID of ${item.mnemonic}`}
                                />
                                <DidQrButton did={item.didId} label={item.mnemonic} />
                              </View>
                            ) : (
                              <Text style={styles.subText}>Uploaded</Text>
                            )}
                          </View>
                          <View
                            role="cell"
                            style={[
                              styles.cell,
                              styles.cellRight,
                              styles.cellGapAfter,
                              columnStyle("versions", 100),
                            ]}
                          >
                            <Text style={styles.numText}>{item.versionCount.toLocaleString()}</Text>
                          </View>
                          <View role="cell" style={[styles.cell, columnStyle("created", 150)]}>
                            <Text style={styles.dateText}>
                              {formatDate(item.createdAt, { withTime: true })}
                            </Text>
                          </View>
                          <View role="cell" style={[styles.cell, columnStyle("updated", 150)]}>
                            {/* One version has never been updated: a dash
                              lets the DIDs that have changed stand out. */}
                            {item.versionCount <= 1 ? (
                              <Text style={styles.dateTextMuted} aria-label="Never updated">
                                —
                              </Text>
                            ) : (
                              <Text style={styles.dateText}>
                                {formatDate(item.updatedAt, { withTime: true })}
                              </Text>
                            )}
                          </View>
                          <View
                            role="cell"
                            style={[styles.cell, styles.cellRight, columnStyle("resolves", 100)]}
                          >
                            <Text style={styles.numText}>
                              {item.totalResolves.toLocaleString()}
                            </Text>
                          </View>
                        </TableRow>
                      );
                    }}
                  />
                )}
              </View>
            </ScrollView>
          )}
        </>
      )}
    </View>
  );
}

/** The DOM `title` attribute (a hover tooltip on web), which React Native's
 *  `Text` types do not list. */
function titleAttr(title: string): Record<string, never> {
  return { title } as unknown as Record<string, never>;
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
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
    marginBottom: 0,
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
  searchField: {
    flex: 1,
    maxWidth: 520,
    marginBottom: 0,
  },
  fieldTight: {
    marginBottom: 0,
  },
  headButton: {
    paddingHorizontal: 0,
    paddingVertical: 0,
    justifyContent: "flex-start",
  },
  searchInput: {
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
  cellGapAfter: {
    paddingRight: spacing.xl,
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
  dateTextMuted: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
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
