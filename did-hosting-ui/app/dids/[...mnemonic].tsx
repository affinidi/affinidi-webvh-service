/**
 * One DID: its addresses, stats, document, names and the actions on it.
 *
 * The cards live in `components/did/`; this route reads the DID, derives what
 * they share, and wires the delegated edits (`useDelegatedTask`) — every
 * change to the document goes through the user's agent, which holds the
 * update key we never will.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { ActivityIndicator, ScrollView, StyleSheet, Text, View } from "react-native";
import { Link, useLocalSearchParams, useRouter } from "expo-router";

import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { useDomains } from "../../components/DomainProvider";
import { RequireAuth } from "../../components/RequireAuth";
import { Button } from "../../components/Button";
import { Heading } from "../../components/Heading";
import { ErrorWithRetry } from "../../components/QueryState";
import { StatsResolutionCard } from "../../components/did/StatsResolutionCard";
import { LazyUsageChart } from "../../components/LazyUsageChart";
import { AgentNamesCard } from "../../components/did/AgentNamesCard";
import { ConsentPanel } from "../../components/did/ConsentPanel";
import { DangerZone } from "../../components/did/DangerZone";
import { DidDocumentCard } from "../../components/did/DidDocumentCard";
import { DidHeader } from "../../components/did/DidHeader";
import { DidDetailsCard, DidStatsCard } from "../../components/did/DidStatsCard";
import { OwnershipCard } from "../../components/did/OwnershipCard";
import { ParametersCard } from "../../components/did/ParametersCard";
import { ScidAliasCard } from "../../components/did/ScidAliasCard";
import { UploadCards } from "../../components/did/UploadCards";
import {
  agentDomainOf,
  agentNameLabel,
  agentNameLocalPart,
  alsoKnownAsOf,
} from "../../components/did/agent-names";
import { confirm, notify, showMessage } from "../../lib/feedback";
import type { DidDetailResponse, LogEntryInfo } from "../../lib/api";
import { ownerMismatchWarning } from "../../lib/delegation-guard";
import { scidAliasesOf } from "../../lib/did-scid";
import { errorMessage, isNotFound } from "../../lib/errors";
import { isRejection } from "../../lib/api";
import { invalidateQueries, setQueryData, useTrustTaskQuery } from "../../lib/query";
import { scidAliasConfirm, scidAliasView, type ScidAliasAction } from "../../lib/scid-alias";
import { colors, fonts, spacing } from "../../lib/theme";
import { useAgentNames } from "../../lib/use-agent-names";
import { useDelegatedTask, type DelegatedResult } from "../../lib/use-delegated-task";
import {
  isWalletTaskRelayAvailable,
  requestAgentNameTask,
  requestDidUpdate,
  requestScidAliasUpdate,
  requestWebsAliasUpdate,
} from "../../lib/wallet";
import { WEBS_AGENT_NAMES_UNSUPPORTED, isDidWebs, planWebsEdit } from "../../lib/webs-edit";

/** A stable empty log, so effects keyed on the entries do not re-run on every
 *  render while nothing has loaded. */
const NO_ENTRIES: LogEntryInfo[] = [];

export default function DidDetail() {
  return (
    <RequireAuth purpose="view DID details">
      <DidDetailScreen />
    </RequireAuth>
  );
}

function DidDetailScreen() {
  const { mnemonic: rawMnemonic } = useLocalSearchParams<{ mnemonic: string | string[] }>();
  const mnemonic = (Array.isArray(rawMnemonic) ? rawMnemonic.join("/") : rawMnemonic) ?? "";
  const api = useApi();
  const { role, did: callerDid } = useAuth();
  const router = useRouter();

  // ── Reads ──────────────────────────────────────────────────────────────────
  const key = useMemo(() => ["did", mnemonic] as const, [mnemonic]);
  const enabled = mnemonic !== "";
  const stats = useTrustTaskQuery(
    [...key, "stats"],
    ({ background }) => api.getStats(mnemonic, { background }),
    { enabled },
  );
  const detailQuery = useTrustTaskQuery(
    [...key, "detail"],
    ({ background }) => api.getDid(mnemonic, { background }),
    { enabled },
  );
  const didDetail = detailQuery.data ?? null;
  // `getDid` already read the log for its summary; its entries are the
  // log shown here, so the page reads `did/log` once per load.
  const logEntries = didDetail?.entries ?? NO_ENTRIES;

  const reload = useCallback(() => void invalidateQueries(key), [key]);

  // ── Shared page state ─────────────────────────────────────────────────────
  const [selectedVersion, setSelectedVersion] = useState(-1);
  // Every (re)load shows the newest version.
  useEffect(() => {
    setSelectedVersion(logEntries.length - 1);
  }, [logEntries]);
  const [editingDoc, setEditingDoc] = useState(false);
  // The upload card's textarea — the document card's "Copy to Upload" fills it.
  const [logContent, setLogContent] = useState("");
  const [loadingRaw, setLoadingRaw] = useState(false);

  // ── Derived ───────────────────────────────────────────────────────────────
  // The owner's own handle, if this service hosts the owner's DID too — the
  // common case, since a VTA usually registers itself here before its DIDs.
  const ownerNameMap = useAgentNames([didDetail?.owner]);
  const ownerNames = ownerNameMap[didDetail?.owner ?? ""] ?? [];
  // Shown beside the delegated-edit actions when this DID belongs to someone
  // other than the identity we signed in as — see `delegation-guard` for why
  // this warns rather than gates.
  const delegationWarning = ownerMismatchWarning(didDetail?.owner, callerDid);
  const withDelegationWarning = (body: string) =>
    delegationWarning ? `${body}\n\n${delegationWarning}` : body;

  const agentDomain = agentDomainOf(didDetail);
  const { domains } = useDomains();
  const knownWatcherUrls = domains.find((d) => d.name === agentDomain)?.watchers ?? [];

  const latestEntry = logEntries[logEntries.length - 1];
  const currentState = latestEntry?.state ?? null;
  const latestVersionId = latestEntry?.versionId ?? null;
  // The names the live document claims, parsed from its `alsoKnownAs`. The
  // signed log is the source of truth — the edge serves exactly what the
  // document claims — so this mirrors what actually resolves.
  const boundNames: string[] = agentDomain
    ? alsoKnownAsOf(currentState?.alsoKnownAs)
        .map((a) => agentNameLocalPart(a, agentDomain))
        // `!== null`, not truthiness: the community name's local part is the
        // empty string, and a truthy filter would drop it.
        .filter((n): n is string => n !== null)
    : [];
  // Parked names come from the host's authoritative registry — they are
  // deliberately absent from the document.
  const parkedNames = (didDetail?.agentNames ?? []).filter((e) => !e.enabled).map((e) => e.name);
  const registry = useMemo(() => (didDetail ? (didDetail.agentNames ?? []) : null), [didDetail]);

  // The did:scid alias the live document lists for itself, if any.
  const scidAliases = scidAliasesOf(didDetail?.didId, currentState?.alsoKnownAs);
  // What the did:scid alias card shows and offers. The state comes from the
  // control plane (`did/info`); who can change it decides the actions.
  const scidAliasPanel = didDetail?.scidAlias
    ? scidAliasView({
        alias: didDetail.scidAlias,
        owner: didDetail.owner,
        canDelegate: isWalletTaskRelayAvailable(),
        preRotation: didDetail.log?.preRotation ?? false,
      })
    : null;

  // ── Delegated edits ───────────────────────────────────────────────────────
  const task = useDelegatedTask({
    latestVersionId,
    notify: showMessage,
    onAccepted: () => {
      setEditingDoc(false);
      reload();
    },
    // While an approval is outstanding, re-read the log in the background:
    // an approval granted on another device applies server-side with nothing
    // dispatched to this tab.
    readLog: () => api.getDidLog(mnemonic, { background: true }),
    onMovedOn: (entries) => {
      setQueryData<DidDetailResponse | undefined>([...key, "detail"], (prev) =>
        prev ? { ...prev, entries } : prev,
      );
      // Background reads, like the watch that noticed: no operator did this.
      void api
        .getDid(mnemonic, { background: true })
        .then((d) => setQueryData([...key, "detail"], d))
        .catch(() => {});
      void api
        .getStats(mnemonic, { background: true })
        .then((s) => setQueryData([...key, "stats"], s))
        .catch(() => {});
      // Deliberately not "your change was applied": the log advancing proves
      // only that it moved, not who moved it.
      notify(
        "info",
        "This DID has moved on",
        `It is now at version ${entries.length}. If that was your approved change, it has been applied and the current document is shown below — otherwise re-apply your edit on top of it.`,
      );
    },
  });

  const noIdentifier = (silent?: boolean): Promise<DelegatedResult> => {
    if (!silent)
      notify("error", "Nothing to change yet", "This DID has no published identifier yet.");
    return Promise.resolve("error");
  };

  /** Publish `document` through the agent, pinned to the version it was
   *  composed against: a human in the approval loop makes the window minutes
   *  wide, and without the pin the VTA would apply our edit on top of someone
   *  else's with every signature still verifying. */
  const publishDocument = (
    document: Record<string, unknown>,
    opts?: { silent?: boolean },
  ): Promise<DelegatedResult> => {
    const didId = didDetail?.didId;
    if (!didId) return noIdentifier(opts?.silent);
    // did:webs has its own update task, which takes designations, not a
    // document — sent as a webvh update, the agent cannot find the DID.
    if (isDidWebs(didId)) return publishWebsAliases(didId, document, opts);
    const expectedVersionId = latestVersionId ?? undefined;
    return task.run(
      () =>
        requestDidUpdate({
          did: didId,
          document,
          ...(expectedVersionId ? { expectedVersionId } : {}),
        }),
      (o) => publishDocument(document, o),
      "Your agent signed and published the update.",
      opts,
    );
  };

  const publishWebsAliases = (
    didId: string,
    document: Record<string, unknown>,
    opts?: { silent?: boolean },
  ): Promise<DelegatedResult> => {
    const plan = planWebsEdit(didId, currentState, document);
    if (plan.kind === "refused") {
      if (!opts?.silent) notify("error", "Can't make this change", plan.reason);
      return Promise.resolve("error");
    }
    return task.run(
      () => requestWebsAliasUpdate({ did: didId, alsoKnownAs: plan.alsoKnownAs }),
      (o) => publishWebsAliases(didId, document, o),
      "Your agent anchored the new aliases and published the update.",
      opts,
    );
  };

  // Park (`enable === false`) or resume an agent name. The VTA reads the
  // current document, edits `alsoKnownAs`, signs and calls the host — so we
  // send only the name.
  const runParkResume = (
    name: string,
    enable: boolean,
    opts?: { silent?: boolean },
  ): Promise<DelegatedResult> => {
    const didId = didDetail?.didId;
    if (!didId) return noIdentifier(opts?.silent);
    if (isDidWebs(didId)) {
      if (!opts?.silent)
        notify("error", "Not available for did:webs", WEBS_AGENT_NAMES_UNSUPPORTED);
      return Promise.resolve("error");
    }
    return task.run(
      () => requestAgentNameTask({ did: didId, name, enable }),
      (o) => runParkResume(name, enable, o),
      enable
        ? `${agentNameLabel(name, agentDomain)} is being served again.`
        : `${agentNameLabel(name, agentDomain)} has been parked.`,
      opts,
    );
  };

  // List or remove the did:scid alias. The version the user looked at is
  // pinned once, so a re-submit sends the byte-identical payload.
  const runScidAlias = (
    scidAlsoKnownAs: boolean,
    expectedVersionId: string | undefined,
    opts?: { silent?: boolean },
  ): Promise<DelegatedResult> => {
    const didId = didDetail?.didId;
    if (!didId) return noIdentifier(opts?.silent);
    return task.run(
      () =>
        requestScidAliasUpdate({
          did: didId,
          scidAlsoKnownAs,
          ...(expectedVersionId ? { expectedVersionId } : {}),
        }),
      (o) => runScidAlias(scidAlsoKnownAs, expectedVersionId, o),
      scidAlsoKnownAs
        ? "Your agent published a version that lists the did:scid alias."
        : "Your agent published a version without the did:scid alias.",
      opts,
      "scidAlias",
    );
  };

  const handleScidAlias = async (action: ScidAliasAction) => {
    const alias = didDetail?.scidAlias;
    if (!alias || !scidAliasPanel) return;
    const expectedVersionId = latestVersionId ?? undefined;
    const ok = await confirm({
      title: action.label,
      body: withDelegationWarning(
        `${scidAliasConfirm(alias, action)}\n\n${scidAliasPanel.warning ?? ""}`.trim(),
      ),
      confirmLabel: action.label,
      destructive: false,
    });
    if (ok) void runScidAlias(action.scidAlsoKnownAs, expectedVersionId);
  };

  /** Publish a version that additionally claims `name` (the local part; the
   *  community name is `""`). `false` when refused before anything was sent. */
  const bindName = (name: string): boolean => {
    if (!agentDomain || !currentState) return false;
    if (boundNames.includes(name)) {
      notify(
        "info",
        "Already bound",
        `${agentNameLabel(name, agentDomain)} is already on this DID.`,
      );
      return false;
    }
    void publishDocument({
      ...currentState,
      alsoKnownAs: [...alsoKnownAsOf(currentState.alsoKnownAs), `https://${agentDomain}/@${name}`],
    });
    return true;
  };

  // Only the root DID may hold `{domain}/@` — the control plane enforces that
  // structurally, so offering it on a tenant slot would advertise something
  // the server refuses.
  const canBindCommunityName =
    mnemonic === ".well-known" &&
    !!agentDomain &&
    !!currentState &&
    !boundNames.includes("") &&
    !parkedNames.includes("");

  const handleBindCommunityName = async () => {
    if (!agentDomain) return;
    const ok = await confirm({
      title: "Bind the community name",
      body:
        `Claim ${agentDomain}/@ for this DID?\n\n` +
        `This is the name of the trust community that owns ${agentDomain}, and it ` +
        `resolves to this root DID. Your agent will publish a new version claiming it.`,
      confirmLabel: "Bind name",
      destructive: false,
    });
    if (ok) bindName("");
  };

  // Remove: publish a version that no longer claims the name. Distinct from
  // parking, which keeps it reserved to this DID.
  const handleUnbindName = async (name: string) => {
    if (!agentDomain || !currentState) return;
    const ok = await confirm({
      title: "Remove name",
      body: `Stop serving ${agentNameLabel(name, agentDomain)}? Your agent will publish a new version that no longer claims it — the redirect stops resolving and the name is freed for anyone to claim.`,
      confirmLabel: "Remove name",
    });
    if (!ok) return;
    const nextAka = alsoKnownAsOf(currentState.alsoKnownAs).filter(
      (a) => agentNameLocalPart(a, agentDomain) !== name,
    );
    await publishDocument({ ...currentState, alsoKnownAs: nextAka });
  };

  // Park and resume are delegated publishes like any other, so the ownership
  // caveat applies — and the confirm is the last thing read before the agent
  // is asked.
  const handleParkName = async (name: string) => {
    const ok = await confirm({
      title: "Park name",
      body: withDelegationWarning(
        `Park ${agentNameLabel(name, agentDomain)}? Your agent publishes a version that stops serving it, but the name stays reserved to this DID — nobody else can claim it, and you can resume it any time.`,
      ),
      confirmLabel: "Park name",
      destructive: false,
    });
    if (ok) void runParkResume(name, false);
  };

  const handleResumeName = async (name: string) => {
    const ok = await confirm({
      title: "Resume name",
      body: withDelegationWarning(
        `Serve ${agentNameLabel(name, agentDomain)} again? Your agent will publish a version that claims it, and the redirect starts resolving.`,
      ),
      confirmLabel: "Resume name",
      destructive: false,
    });
    if (ok) void runParkResume(name, true);
  };

  // ── Raw log ────────────────────────────────────────────────────────────────
  const loadRawLog = async () => {
    setLoadingRaw(true);
    try {
      setLogContent(await api.getRawLog(mnemonic));
    } catch (e: unknown) {
      notify("error", "Could not load did.jsonl", errorMessage(e, "Failed to load raw log"));
    } finally {
      setLoadingRaw(false);
    }
  };

  const consentPanel = (
    <ConsentPanel
      consent={task.consent}
      publishing={task.publishing}
      onPublishNow={task.resubmitNow}
    />
  );
  const logEntryCount = didDetail?.log?.logEntryCount ?? 0;
  const canDelegate = isWalletTaskRelayAvailable();

  // A path that names no DID — or one this session may not see, which the
  // control plane answers the same way — gets a page saying so, and none of
  // the actions that would only fail on it.
  if (
    !didDetail &&
    detailQuery.error != null &&
    (isNotFound(detailQuery.error) || isRejection(detailQuery.error, "permissionDenied"))
  ) {
    return (
      <View style={styles.notFound}>
        <Heading level={1}>DID not found</Heading>
        <Text style={styles.notFoundText}>
          There is no DID at “{mnemonic}”, or it is not one you can see. Check the address, or find
          it in the DID list.
        </Text>
        <Link href="/dids" asChild>
          <Button label="Go to the DID list" />
        </Link>
      </View>
    );
  }
  if (!didDetail) {
    return (
      <View style={styles.notFound}>
        {detailQuery.error != null ? (
          <ErrorWithRetry
            error={detailQuery.error}
            what="this DID"
            onRetry={() => void detailQuery.refetch()}
          />
        ) : (
          <ActivityIndicator color={colors.accent} size="large" aria-label="Loading the DID" />
        )}
      </View>
    );
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.wide}>
        <DidHeader
          mnemonic={mnemonic}
          detail={didDetail}
          scidAliases={scidAliases}
          boundNames={boundNames}
          agentDomain={agentDomain}
          ownerNames={ownerNames}
        />

        <DidStatsCard
          stats={stats.data}
          error={stats.error ? errorMessage(stats.error, "Could not load statistics") : null}
        />

        {didDetail?.log && <DidDetailsCard detail={didDetail} />}

        <LazyUsageChart mnemonic={mnemonic} />

        {logEntries.length > 0 && (
          <DidDocumentCard
            logEntries={logEntries}
            selectedVersion={selectedVersion}
            onSelectVersion={setSelectedVersion}
            editing={editingDoc}
            onEditingChange={setEditingDoc}
            canPublish={canDelegate}
            publishing={task.publishing}
            onPublish={(doc) => void publishDocument(doc)}
            delegationWarning={delegationWarning}
            consentPanel={consentPanel}
          />
        )}

        {didDetail?.scidAlias && scidAliasPanel && (
          <ScidAliasCard
            alias={didDetail.scidAlias}
            panel={scidAliasPanel}
            publishing={task.publishing}
            onAction={handleScidAlias}
            consentPanel={!editingDoc && task.consentOrigin === "scidAlias" ? consentPanel : null}
          />
        )}

        {logEntries.length > 0 && (
          <AgentNamesCard
            mnemonic={mnemonic}
            agentDomain={agentDomain}
            hasDidId={!!didDetail?.didId}
            registry={registry}
            boundNames={boundNames}
            parkedNames={parkedNames}
            canBindCommunityName={canBindCommunityName}
            canDelegate={canDelegate}
            publishing={task.publishing}
            onBind={bindName}
            onBindCommunityName={handleBindCommunityName}
            onPark={handleParkName}
            onUnbind={handleUnbindName}
            onResume={handleResumeName}
            consentPanel={!editingDoc && task.consentOrigin !== "scidAlias" ? consentPanel : null}
          />
        )}

        {logEntries.length > 0 && (
          <ParametersCard latest={latestEntry} knownWatcherUrls={knownWatcherUrls} />
        )}

        <UploadCards
          mnemonic={mnemonic}
          versionCount={didDetail?.versionCount ?? 0}
          logContent={logContent}
          onLogContentChange={setLogContent}
          loadingRaw={loadingRaw}
          onLoadCurrent={() => void loadRawLog()}
          onUploaded={reload}
          notify={showMessage}
        />

        {didDetail && (role === "admin" || (callerDid && callerDid === didDetail.owner)) && (
          <OwnershipCard
            mnemonic={mnemonic}
            isAdmin={role === "admin"}
            onChanged={(record) =>
              setQueryData<DidDetailResponse | undefined>([...key, "detail"], (prev) =>
                prev ? { ...prev, owner: record.owner, updatedAt: record.updatedAt } : prev,
              )
            }
            notify={showMessage}
          />
        )}

        <StatsResolutionCard mnemonic={mnemonic} isAdmin={role === "admin"} />

        <DangerZone
          mnemonic={mnemonic}
          versionCount={didDetail.versionCount}
          logEntryCount={logEntryCount}
          suspended={didDetail.disabled}
          onRolledBack={reload}
          onStateChanged={() => {
            reload();
            void invalidateQueries(["dids"]);
          }}
          onDeleted={() => {
            void invalidateQueries(["dids"]);
            router.replace("/dids");
          }}
        />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.bgPrimary,
  },
  content: {
    padding: spacing.xl,
  },
  notFound: {
    flex: 1,
    padding: spacing.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgPrimary,
    gap: spacing.md,
  },
  notFoundText: {
    fontFamily: fonts.regular,
    fontSize: 15,
    color: colors.textSecondary,
    textAlign: "center",
    maxWidth: 520,
  },
  wide: {
    maxWidth: 1200,
    alignSelf: "center",
    width: "100%",
  },
});
