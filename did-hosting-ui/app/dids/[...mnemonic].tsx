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
import { ChipInput } from "../../components/ChipInput";
import { UsageChart } from "../../components/UsageChart";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { showAlert, showConfirm } from "../../lib/alert";
import {
  isWalletTaskRelayAvailable,
  requestDidUpdate,
  requestAgentNameTask,
  digestPrefix,
  type TaskConsentRequired,
  type RequestTaskOutcome,
} from "../../lib/wallet";
import type {
  DidStats,
  DidDetailResponse,
  LogEntryInfo,
  WatcherSyncStatus,
} from "../../lib/api";

// ---------------------------------------------------------------------------
// Agent-name helpers
// ---------------------------------------------------------------------------

/** The hosting domain a name is scoped to — the DID's own host. Prefer the
 *  record's tagged `domain`; fall back to the host segment of the `did:webvh`
 *  identifier (percent-decoded, e.g. `localhost%3A8534` → `localhost:8534`). */
function agentDomainOf(detail: DidDetailResponse | null): string | null {
  if (detail?.domain) return detail.domain;
  const didId = detail?.didId;
  if (!didId) return null;
  // did:webvh:<scid>:<host>:<path...> → host at index 3.
  const parts = didId.split(":");
  if (parts.length < 5 || parts[0] !== "did") return null;
  try {
    return decodeURIComponent(parts[3]);
  } catch {
    return parts[3];
  }
}

/** If `aka` is an agent name (`…/@local`) on `domain`, return its local part.
 *  Host match is case-insensitive; the local part is returned verbatim (the
 *  spec compares it case-sensitively). */
function agentNameLocalPart(aka: string, domain: string): string | null {
  const noScheme = aka.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const marker = noScheme.indexOf("/@");
  if (marker < 0) return null;
  const host = noScheme.slice(0, marker);
  const local = noScheme.slice(marker + 2).split("/")[0];
  if (!local || host.toLowerCase() !== domain.toLowerCase()) return null;
  return local;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function DidDetail() {
  const { mnemonic: rawMnemonic } = useLocalSearchParams<{ mnemonic: string | string[] }>();
  const mnemonic = Array.isArray(rawMnemonic) ? rawMnemonic.join("/") : rawMnemonic;
  const api = useApi();
  const { isAuthenticated, role, did: callerDid } = useAuth();
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
  const [showChangeOwner, setShowChangeOwner] = useState(false);
  const [newOwnerInput, setNewOwnerInput] = useState("");
  const [changingOwner, setChangingOwner] = useState(false);
  const [editingDoc, setEditingDoc] = useState(false);
  const [docEditValue, setDocEditValue] = useState("");
  // Delegated publish: the VTA holds the update key, so we propose and it decides.
  const [publishing, setPublishing] = useState(false);
  const [consent, setConsent] = useState<TaskConsentRequired | null>(null);
  // The exact re-submit the outstanding approval is bound to — a document
  // publish OR an agent-name park/resume.
  //
  // The approval is bound to a digest of the *payload*, so a retry MUST send
  // the identical request. If the user edited the textarea (or typed a
  // different name) while their phone was buzzing and we then submitted the new
  // input, the digest would not match, the grant would not be found, and the
  // VTA would raise a fresh approval — the *safe* failure, but a baffling one.
  // Pinning the exact re-submit closure keeps "I approved it" meaning what the
  // user thinks it means. A ref, not state: it is read only from the
  // grant-event handler and the manual button, never rendered.
  const resubmitRef = useRef<
    ((opts?: { silent?: boolean }) => Promise<"accepted" | "consent" | "error">) | null
  >(null);
  const [editingParams, setEditingParams] = useState(false);
  const [paramWatchers, setParamWatchers] = useState<string[]>([]);
  const [paramWitnesses, setParamWitnesses] = useState<string[]>([]);
  const [paramAlsoKnownAs, setParamAlsoKnownAs] = useState<string[]>([]);
  const [paramPortable, setParamPortable] = useState(false);
  const [paramTtl, setParamTtl] = useState<string>("");
  const [knownWatcherUrls, setKnownWatcherUrls] = useState<string[]>([]);
  // Agent names (`/@alice`)
  const [nameInput, setNameInput] = useState("");
  const [nameStatus, setNameStatus] = useState<
    "checking" | "available" | "taken" | "reserved" | "error" | null
  >(null);
  const nameDebounce = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Resume a parked name — typed, because a parked name is absent from the
  // document's `alsoKnownAs`, so the served-names list can't surface it.
  const [resumeInput, setResumeInput] = useState("");

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

  // The hosting domain this DID's names are scoped to.
  const agentDomain = agentDomainOf(didDetail);

  // The names currently claimed by the live document, parsed from its
  // `alsoKnownAs`. Source of truth is the signed log — the edge serves exactly
  // what the document claims — so this list mirrors what actually resolves.
  const currentState = logEntries[logEntries.length - 1]?.state ?? null;
  const boundNames: string[] = agentDomain
    ? (Array.isArray(currentState?.alsoKnownAs) ? currentState!.alsoKnownAs : [])
        .map((a: unknown) => (typeof a === "string" ? agentNameLocalPart(a, agentDomain) : null))
        .filter((n): n is string => !!n)
    : [];

  // Debounced availability probe as the user types a new name.
  useEffect(() => {
    if (nameDebounce.current) clearTimeout(nameDebounce.current);
    const trimmed = nameInput.trim().replace(/^@/, "");
    if (trimmed.length < 2 || !agentDomain) {
      setNameStatus(null);
      return;
    }
    setNameStatus("checking");
    nameDebounce.current = setTimeout(() => {
      api
        .checkAgentName(trimmed, agentDomain)
        .then((r) =>
          setNameStatus(r.reserved ? "reserved" : r.available ? "available" : "taken"),
        )
        .catch(() => setNameStatus("error"));
    }, 400);
    return () => {
      if (nameDebounce.current) clearTimeout(nameDebounce.current);
    };
  }, [nameInput, agentDomain, api]);

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

  const handleChangeOwner = async () => {
    if (!mnemonic) return;
    const newOwner = newOwnerInput.trim();
    if (!newOwner) return;
    showConfirm(
      "Change Owner",
      `Transfer ownership of "${mnemonic}" to ${newOwner}? The new owner must already exist in the ACL.`,
      async () => {
        setChangingOwner(true);
        try {
          const result = await api.changeOwner(mnemonic, newOwner);
          setDidDetail((prev) =>
            prev ? { ...prev, owner: result.owner, updatedAt: result.updatedAt } : prev,
          );
          setNewOwnerInput("");
          setShowChangeOwner(false);
          showAlert("Success", "DID owner changed");
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : "Change owner failed";
          showAlert("Error", msg);
        } finally {
          setChangingOwner(false);
        }
      },
    );
  };

  /**
   * Publish the edited document through the user's agent.
   *
   * We do not hold this DID's update key and never will. We propose the new
   * document; the VTA dry-runs its own update handler against the authoritative
   * log to work out what our edit would actually do — including the update-key
   * rotation that any document change causes, which is nowhere in what we sent
   * and which we could not have told the user about if we tried — and then
   * decides, per the user's policy, whether a human has to approve it.
   */
  // Result of one publish attempt, so the auto-apply poll can decide whether to
  // keep waiting (`consent`), stop on success (`accepted`), or back off (`error`).
  type PublishResult = "accepted" | "consent" | "error";

  // `opts.silent` is the background poll: it suppresses the toast and the
  // `publishing` spinner (so the button doesn't flicker "Checking…" on every
  // tick) but still resolves the approval — a granted update is always announced.
  // Run one delegated task through the wallet: submit, and on a
  // `consentRequired` refusal pin the exact re-submit so the grant event (and
  // the manual button) can replay it byte-identically. `submit` and `resubmit`
  // MUST produce the same payload, or the approved digest won't match.
  const runDelegatedTask = async (
    submit: () => Promise<RequestTaskOutcome>,
    resubmit: (opts?: { silent?: boolean }) => Promise<PublishResult>,
    successMsg: string,
    opts?: { silent?: boolean },
  ): Promise<PublishResult> => {
    const silent = opts?.silent ?? false;
    if (!silent) setPublishing(true);
    try {
      const outcome = await submit();
      if (outcome.kind === "consentRequired") {
        resubmitRef.current = resubmit;
        setConsent(outcome);
        return "consent";
      }
      resubmitRef.current = null;
      setConsent(null);
      setEditingDoc(false);
      showAlert("Done", successMsg);
      loadData();
      return "accepted";
    } catch (e: unknown) {
      if (!silent) showAlert("Error", e instanceof Error ? e.message : "The request failed.");
      return "error";
    } finally {
      if (!silent) setPublishing(false);
    }
  };

  const handlePublishViaVta = async (
    retryOf?: Record<string, unknown>,
    opts?: { silent?: boolean },
  ): Promise<PublishResult> => {
    const didId = didDetail?.didId;
    if (!didId) {
      if (!opts?.silent) showAlert("Error", "This DID has no published identifier yet.");
      return "error";
    }
    let document: Record<string, unknown>;
    if (retryOf) {
      document = retryOf;
    } else {
      try {
        document = JSON.parse(docEditValue) as Record<string, unknown>;
      } catch {
        if (!opts?.silent) showAlert("Error", "The document is not valid JSON.");
        return "error";
      }
    }
    // The version we based this edit on. A human in the approval loop makes the
    // window minutes wide, so the log really can move underneath us; without this
    // the VTA would apply our edit on top of someone else's and every signature in
    // the resulting chain would still verify.
    const expectedVersionId = logEntries[logEntries.length - 1]?.versionId ?? undefined;
    return runDelegatedTask(
      () =>
        requestDidUpdate({
          did: didId,
          document,
          ...(expectedVersionId ? { expectedVersionId } : {}),
        }),
      (o) => handlePublishViaVta(document, o),
      "Your agent signed and published the update.",
      opts,
    );
  };

  // Park (`enable === false`) or resume (`enable === true`) an agent name
  // through the agent. The VTA reads the current document, edits `alsoKnownAs`,
  // signs, and calls the host — so unlike a bind/remove we send only the name.
  const runParkResume = (
    name: string,
    enable: boolean,
    opts?: { silent?: boolean },
  ): Promise<PublishResult> => {
    const didId = didDetail?.didId;
    if (!didId) {
      if (!opts?.silent) showAlert("Error", "This DID has no published identifier yet.");
      return Promise.resolve("error");
    }
    return runDelegatedTask(
      () => requestAgentNameTask({ did: didId, name, enable }),
      (o) => runParkResume(name, enable, o),
      enable ? `@${name} is being served again.` : `@${name} has been parked.`,
      opts,
    );
  };

  // ── Auto-apply: run the moment the approval lands ──────────────────────────
  //
  // Event-driven only. The wallet emits `vtawallet:consentgranted` (with the
  // payloadDigest) the instant the VTA reports the grant, and we replay the
  // *pinned* re-submit exactly once — its payload digest matches the
  // outstanding approval, so the VTA applies it. The manual button is the
  // fallback for a missed event.
  //
  // There is deliberately NO timer poll. Every re-submit goes through the
  // wallet's `requestTask`, which shows an un-skippable worker-mode confirm.
  // A blind re-submit loop would re-open that popup on every tick; a single
  // re-submit on the grant event is the only safe re-attempt.
  const autoApplying = consent != null;

  // Event-driven: re-attempt the instant the wallet reports our approval landed.
  useEffect(() => {
    const digest = consent?.payloadDigest;
    if (!digest || typeof window === "undefined" || !window.addEventListener) return;
    const onGranted = (ev: Event) => {
      const detail = (ev as CustomEvent).detail as { payloadDigest?: string } | undefined;
      // Only the approval we're waiting on — ignore events for other tasks.
      if (detail?.payloadDigest !== digest) return;
      void resubmitRef.current?.({ silent: true });
    };
    window.addEventListener("vtawallet:consentgranted", onGranted);
    return () => window.removeEventListener("vtawallet:consentgranted", onGranted);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [consent?.payloadDigest]);

  // Bind a name: publish a new version whose `alsoKnownAs` claims
  // `https://<domain>/@<name>`. The edge derives the served name from that
  // signed claim, so the redirect starts resolving once the agent publishes —
  // no separate provisioning call needed.
  const handleBindName = async () => {
    const name = nameInput.trim().replace(/^@/, "");
    if (!name || !agentDomain || !currentState) return;
    if (boundNames.includes(name)) {
      showAlert("Already bound", `@${name} is already on this DID.`);
      return;
    }
    const currentAka: string[] = Array.isArray(currentState.alsoKnownAs)
      ? currentState.alsoKnownAs.filter((a: unknown) => typeof a === "string")
      : [];
    const nextDoc = {
      ...currentState,
      alsoKnownAs: [...currentAka, `https://${agentDomain}/@${name}`],
    };
    setNameInput("");
    setNameStatus(null);
    await handlePublishViaVta(nextDoc);
  };

  // Remove a name: publish a version that no longer claims it. The redirect
  // stops resolving and the name is freed for anyone to reclaim. Distinct from
  // parking (below), which keeps the name reserved to this DID.
  const handleUnbindName = (name: string) => {
    if (!agentDomain || !currentState) return;
    showConfirm(
      "Remove name",
      `Stop serving @${name}? Your agent will publish a new version that no longer claims it — the redirect stops resolving and the name is freed for anyone to claim.`,
      async () => {
        const currentAka: string[] = Array.isArray(currentState.alsoKnownAs)
          ? currentState.alsoKnownAs.filter((a: unknown) => typeof a === "string")
          : [];
        const nextAka = currentAka.filter(
          (a) => agentNameLocalPart(a, agentDomain) !== name,
        );
        await handlePublishViaVta({ ...currentState, alsoKnownAs: nextAka });
      },
    );
  };

  // Park a name: stop serving it but keep it reserved to this DID. Unlike
  // remove, the agent runs a dedicated task that both drops the claim and tells
  // the host to hold the reservation — so nobody else can take it while parked.
  const handleParkName = (name: string) => {
    showConfirm(
      "Park name",
      `Park @${name}? Your agent publishes a version that stops serving it, but the name stays reserved to this DID — nobody else can claim it, and you can resume it any time.`,
      () => void runParkResume(name, false),
    );
  };

  // Resume a parked name (typed by the user — a parked name isn't in the
  // document, so it can't be listed).
  const handleResumeName = () => {
    const name = resumeInput.trim().replace(/^@/, "");
    if (!name) return;
    setResumeInput("");
    void runParkResume(name, true);
  };

  // The cross-device approval code, shown wherever a publish is awaiting the
  // user's approval — a plain document edit OR an agent-name change, since both
  // go through the same delegated-publish flow. Returns null when idle.
  const consentMatchPanel = () =>
    consent ? (
      <View
        style={{
          marginTop: spacing.md,
          padding: spacing.md,
          borderWidth: 1,
          borderColor: colors.warning ?? colors.border,
          borderRadius: radii.sm,
          gap: spacing.sm,
        }}
      >
        <Text style={[styles.sectionTitle, { marginBottom: 0 }]}>
          Approve this on your device
        </Text>
        <Text style={styles.hint}>
          {consent.sideEffects === "destructive"
            ? "This cannot be undone. Your agent has sent the change to your approving device, which will ask you to TYPE the code below. Do not type it from memory of this screen — read it from here, and only approve if the device shows the same code."
            : "Your agent has sent this change to your approving device, with a description of what it will do. Check that the code shown there matches the one below, then approve it."}
        </Text>
        <Text
          style={{
            fontFamily: fonts.mono,
            fontSize: 28,
            letterSpacing: 6,
            color: colors.textPrimary,
            textAlign: "center",
            paddingVertical: spacing.sm,
          }}
          selectable
        >
          {digestPrefix(consent.payloadDigest)}
        </Text>
        <Text style={styles.hint}>
          If the codes differ, deny it. A code that does not match means the
          change your device is showing you is not the change that would be made.
        </Text>
        {autoApplying && (
          <Text style={[styles.hint, { textAlign: "center" }]}>
            Waiting for your approval — this will publish automatically the
            moment you approve.
          </Text>
        )}
        <Pressable
          style={[styles.outlineButton, publishing && styles.disabled]}
          onPress={() => void resubmitRef.current?.()}
          disabled={publishing}
        >
          <Text style={styles.outlineButtonText}>
            {publishing
              ? "Checking..."
              : autoApplying
                ? "Publish now"
                : "I have approved it — publish"}
          </Text>
        </Pressable>
      </View>
    ) : null;

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
                <Text style={styles.statValue}>{stats.totalResolves.toLocaleString()}</Text>
                <Text style={styles.statLabel}>Resolves</Text>
              </View>
              <View style={styles.statItem}>
                <Text style={styles.statValue}>{stats.totalUpdates.toLocaleString()}</Text>
                <Text style={styles.statLabel}>Updates</Text>
              </View>
              <View style={styles.statItem}>
                <Text style={styles.statSmall}>
                  {formatDate(stats.lastResolvedAt)}
                </Text>
                <Text style={styles.statLabel}>Last Resolved</Text>
              </View>
              <View style={styles.statItem}>
                <Text style={styles.statSmall}>
                  {formatDate(stats.lastUpdatedAt)}
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
              {(didDetail.method ?? didDetail.log.method) && (
                <View style={styles.detailRow}>
                  <Text style={styles.detailLabel}>Method</Text>
                  <Text style={styles.detailValueMono}>
                    {didDetail.method ?? didDetail.log.method}
                  </Text>
                </View>
              )}
              {didDetail.domain && (
                <View style={styles.detailRow}>
                  <Text style={styles.detailLabel}>Domain</Text>
                  <Text style={styles.detailValueMono}>
                    {didDetail.domain}
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
              <>
                <TextInput
                  style={[styles.textarea, { minHeight: 300 }]}
                  value={docEditValue}
                  onChangeText={setDocEditValue}
                  multiline
                />
                {isWalletTaskRelayAvailable() && (
                  <View style={{ marginTop: spacing.md, gap: spacing.sm }}>
                    <Pressable
                      style={[styles.button, publishing && styles.disabled]}
                      onPress={() => void handlePublishViaVta()}
                      disabled={publishing}
                    >
                      <Text style={styles.buttonText}>
                        {publishing ? "Asking your agent..." : "Publish with my agent"}
                      </Text>
                    </Pressable>
                    <Text style={styles.hint}>
                      Your agent holds this DID&apos;s update key. It will work out what this
                      change actually does before it signs anything — including effects that
                      are not visible in the document above.
                    </Text>
                  </View>
                )}

                {/*
                  The cross-device match. Extracted to `consentMatchPanel` so
                  the same approval code renders for an agent-name change too;
                  see the note there.

                  Every other check in this design assumes an honest device. Only
                  this one survives a compromised one, because only this one moves
                  the comparison into the user's head, across two screens that an
                  attacker would have to control both of. It is the reason this is
                  a code to compare and not a "waiting for approval..." spinner —
                  a spinner is something you wait out; a code is something you
                  check.
                */}
                {consentMatchPanel()}
              </>
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

        {/* Agent names */}
        {logEntries.length > 0 && (
          <View style={styles.card}>
            <Text style={styles.sectionTitle}>Agent Names</Text>
            <Text style={styles.hint}>
              A human-memorable shortcut —{" "}
              {agentDomain ? `${agentDomain}/@name` : "yourdomain/@name"} — that
              redirects to this DID. A name is served because the signed document
              claims it via alsoKnownAs, so binding one publishes a new version
              through your agent.
            </Text>

            {boundNames.length > 0 ? (
              <View style={{ gap: spacing.sm, marginTop: spacing.md }}>
                {boundNames.map((name) => (
                  <View
                    key={name}
                    style={{
                      flexDirection: "row",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: spacing.md,
                    }}
                  >
                    <Text style={{ fontFamily: fonts.mono, color: colors.textPrimary }}>
                      @{name}
                    </Text>
                    <View style={{ flexDirection: "row", gap: spacing.sm }}>
                      <Pressable
                        style={[styles.smallButton, publishing && styles.disabled]}
                        onPress={() => handleParkName(name)}
                        disabled={publishing}
                      >
                        <Text style={styles.smallButtonText}>Park</Text>
                      </Pressable>
                      <Pressable
                        style={[styles.smallButton, publishing && styles.disabled]}
                        onPress={() => handleUnbindName(name)}
                        disabled={publishing}
                      >
                        <Text style={styles.smallButtonText}>Remove</Text>
                      </Pressable>
                    </View>
                  </View>
                ))}
              </View>
            ) : (
              <Text style={[styles.hint, { marginTop: spacing.sm }]}>
                No names bound yet.
              </Text>
            )}

            {!agentDomain ? (
              <Text style={[styles.hint, { marginTop: spacing.md }]}>
                This DID has no published document yet — publish one before
                binding a name.
              </Text>
            ) : isWalletTaskRelayAvailable() ? (
              <View style={{ marginTop: spacing.md, gap: spacing.sm }}>
                <View
                  style={{ flexDirection: "row", alignItems: "center", gap: spacing.sm }}
                >
                  <Text style={{ color: colors.textSecondary, fontFamily: fonts.mono }}>
                    @
                  </Text>
                  <input
                    type="text"
                    value={nameInput}
                    onChange={(e) => setNameInput(e.target.value)}
                    placeholder="alice"
                    disabled={publishing}
                    style={{
                      flex: 1,
                      backgroundColor: colors.bgPrimary,
                      color: colors.textPrimary,
                      border: `1px solid ${colors.border}`,
                      borderRadius: radii.sm,
                      padding: "6px 10px",
                      fontFamily: fonts.mono,
                      fontSize: 14,
                    }}
                  />
                  <Pressable
                    style={[
                      styles.button,
                      { marginTop: 0 },
                      (publishing || nameStatus !== "available") && styles.disabled,
                    ]}
                    onPress={() => void handleBindName()}
                    disabled={publishing || nameStatus !== "available"}
                  >
                    <Text style={styles.buttonText}>
                      {publishing ? "Asking your agent..." : "Bind name"}
                    </Text>
                  </Pressable>
                </View>
                {nameStatus && (
                  <Text
                    style={{
                      fontSize: 13,
                      color:
                        nameStatus === "available"
                          ? colors.success
                          : nameStatus === "checking"
                            ? colors.textSecondary
                            : colors.error,
                    }}
                  >
                    {nameStatus === "checking"
                      ? "Checking…"
                      : nameStatus === "available"
                        ? "Available"
                        : nameStatus === "taken"
                          ? "Already taken on this domain"
                          : nameStatus === "reserved"
                            ? "Reserved by the host"
                            : "Could not check availability"}
                  </Text>
                )}
                {/* Resume a parked name. Parked names aren't in the document,
                    so they can't be listed — the owner types the one they
                    parked. */}
                <View
                  style={{
                    flexDirection: "row",
                    alignItems: "center",
                    gap: spacing.sm,
                    marginTop: spacing.sm,
                  }}
                >
                  <Text style={{ color: colors.textSecondary, fontFamily: fonts.mono }}>
                    @
                  </Text>
                  <input
                    type="text"
                    value={resumeInput}
                    onChange={(e) => setResumeInput(e.target.value)}
                    placeholder="resume a parked name"
                    disabled={publishing}
                    style={{
                      flex: 1,
                      backgroundColor: colors.bgPrimary,
                      color: colors.textPrimary,
                      border: `1px solid ${colors.border}`,
                      borderRadius: radii.sm,
                      padding: "6px 10px",
                      fontFamily: fonts.mono,
                      fontSize: 14,
                    }}
                  />
                  <Pressable
                    style={[
                      styles.smallButton,
                      (publishing || resumeInput.trim().length < 2) && styles.disabled,
                    ]}
                    onPress={handleResumeName}
                    disabled={publishing || resumeInput.trim().length < 2}
                  >
                    <Text style={styles.smallButtonText}>Resume</Text>
                  </Pressable>
                </View>
                {/* The approval code lands here when a name change is pending
                    (the doc editor shows it in its own section when open). */}
                {!editingDoc && consentMatchPanel()}
              </View>
            ) : (
              <Text style={[styles.hint, { marginTop: spacing.md }]}>
                Binding a name needs a connected agent wallet to sign the update.
              </Text>
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

        {/* Change Owner — visible to admins or the current owner */}
        {didDetail &&
          (role === "admin" || (callerDid && callerDid === didDetail.owner)) && (
            <View style={styles.card}>
              <View style={styles.sectionTitleRow}>
                <Text style={styles.sectionTitle}>Ownership</Text>
                <Pressable
                  style={styles.smallButton}
                  onPress={() => {
                    setShowChangeOwner(!showChangeOwner);
                    if (showChangeOwner) setNewOwnerInput("");
                  }}
                >
                  <Text style={styles.smallButtonText}>
                    {showChangeOwner ? "Cancel" : "Change Owner"}
                  </Text>
                </Pressable>
              </View>
              <Text style={styles.hint}>
                Transfer this DID to a different identity. The new owner must
                already be in the ACL.
              </Text>
              {showChangeOwner && (
                <>
                  <TextInput
                    style={styles.ownerInput}
                    placeholder="did:webvh:..."
                    placeholderTextColor={colors.textTertiary}
                    value={newOwnerInput}
                    onChangeText={setNewOwnerInput}
                    autoCapitalize="none"
                    autoCorrect={false}
                  />
                  <Pressable
                    style={[
                      styles.button,
                      (!newOwnerInput.trim() || changingOwner) && styles.disabled,
                    ]}
                    onPress={handleChangeOwner}
                    disabled={!newOwnerInput.trim() || changingOwner}
                  >
                    <Text style={styles.buttonText}>
                      {changingOwner ? "Transferring..." : "Transfer Ownership"}
                    </Text>
                  </Pressable>
                </>
              )}
            </View>
          )}

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
  ownerInput: {
    backgroundColor: colors.bgPrimary,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: radii.sm,
    padding: spacing.md,
    color: colors.textPrimary,
    fontSize: 13,
    fontFamily: fonts.mono,
    marginBottom: spacing.md,
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
