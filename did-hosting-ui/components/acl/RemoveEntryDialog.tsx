import { useEffect, useRef, useState, type ReactNode } from "react";
import { ActivityIndicator, ScrollView, StyleSheet, Text, View } from "react-native";

import type { DidRecord } from "../../lib/api";
import { errorMessage } from "../../lib/errors";
import { notify } from "../../lib/feedback";
import { plural } from "../../lib/plural";
import { invalidateQueries } from "../../lib/query";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { useApi } from "../ApiProvider";
import { Button, type ButtonHandle } from "../Button";
import { Dialog } from "../Dialog";
import { Field } from "../Field";
import { ACL_KEY } from "./keys";

type DidStatus = "pending" | "deleting" | "deleted" | "failed";

type Phase =
  | { kind: "loading" }
  | { kind: "choose"; dids: DidRecord[]; listError: string | null }
  | { kind: "running"; dids: DidRecord[]; status: Record<string, DidStatus>; step: string }
  | {
      kind: "partial";
      dids: DidRecord[];
      status: Record<string, DidStatus>;
      errors: Record<string, string>;
      aclError: string | null;
    };

/** The phrase typed to confirm deleting an owner's DIDs. */
export function deletePhrase(count: number): string {
  return `delete ${count}`;
}

/**
 * Remove an ACL entry — one dialog, three choices.
 *
 * The entry may own DIDs. The dialog lists them and offers: remove access
 * only (the DIDs stay, still owned by that DID), remove access *and* delete
 * every listed DID (typed confirmation), or cancel. Deleting runs one DID at a
 * time with each one's progress shown; if any fails, the access entry is
 * kept and the failures are listed with a retry, so a half-finished removal is
 * never reported as done.
 */
export function RemoveEntryDialog({ did, onClose }: { did: string; onClose: () => void }) {
  const api = useApi();
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [typed, setTyped] = useState("");
  // Focus starts on Cancel, so a stray Enter never removes anything.
  const cancelRef = useRef<ButtonHandle>(null);
  const focusKey = phase.kind === "choose" || phase.kind === "loading" ? phase.kind : null;
  useEffect(() => {
    if (!focusKey) return;
    const focus = () => (cancelRef.current as unknown as HTMLElement | null)?.focus?.();
    focus();
    const t = setTimeout(focus, 0);
    return () => clearTimeout(t);
  }, [focusKey]);

  useEffect(() => {
    let cancelled = false;
    api
      .listDids(did)
      .then((dids) => !cancelled && setPhase({ kind: "choose", dids, listError: null }))
      .catch(
        (e: unknown) =>
          !cancelled &&
          setPhase({
            kind: "choose",
            dids: [],
            listError: errorMessage(e, "Could not check which DIDs this account owns."),
          }),
      );
    return () => {
      cancelled = true;
    };
  }, [api, did]);

  const removeAccess = async (): Promise<string | null> => {
    try {
      await api.deleteAcl(did);
      return null;
    } catch (e: unknown) {
      return errorMessage(e, "Could not remove the access entry.");
    }
  };

  const finish = async (deletedCount: number) => {
    await invalidateQueries(ACL_KEY, ["dids"]);
    notify(
      "success",
      "Access removed",
      deletedCount > 0
        ? `${did} no longer has access, and ${plural(deletedCount, "DID was", "DIDs were")} deleted.`
        : `${did} no longer has access.`,
    );
    onClose();
  };

  const accessOnly = async (dids: DidRecord[]) => {
    setPhase({ kind: "running", dids: [], status: {}, step: "Removing access…" });
    const aclError = await removeAccess();
    if (aclError) {
      setPhase({ kind: "partial", dids, status: {}, errors: {}, aclError });
      return;
    }
    await finish(0);
  };

  /** Delete `targets` (each not yet deleted), then remove access if all went. */
  const deleteThenRemove = async (
    dids: DidRecord[],
    prior: Record<string, DidStatus> = {},
  ): Promise<void> => {
    const status: Record<string, DidStatus> = { ...prior };
    for (const d of dids) if (status[d.mnemonic] !== "deleted") status[d.mnemonic] = "pending";
    const errors: Record<string, string> = {};
    const show = (step: string) => setPhase({ kind: "running", dids, status: { ...status }, step });
    for (const d of dids) {
      if (status[d.mnemonic] === "deleted") continue;
      status[d.mnemonic] = "deleting";
      show(`Deleting ${d.mnemonic}…`);
      try {
        await api.deleteDid(d.mnemonic);
        status[d.mnemonic] = "deleted";
      } catch (e: unknown) {
        status[d.mnemonic] = "failed";
        errors[d.mnemonic] = errorMessage(e, "Delete failed");
      }
    }
    const failed = Object.keys(errors).length;
    const deleted = dids.filter((d) => status[d.mnemonic] === "deleted").length;
    if (failed > 0) {
      // Keep the entry: the owner still owns DIDs, and removing their access
      // now would orphan them.
      void invalidateQueries(["dids"]);
      setPhase({ kind: "partial", dids, status, errors, aclError: null });
      return;
    }
    show("Removing access…");
    const aclError = await removeAccess();
    if (aclError) {
      setPhase({ kind: "partial", dids, status, errors, aclError });
      return;
    }
    await finish(deleted);
  };

  const running = phase.kind === "running";
  const close = () => {
    if (!running) onClose();
  };

  let body: ReactNode = null;
  let actions: ReactNode = null;

  if (phase.kind === "loading") {
    body = <ActivityIndicator color={colors.accent} aria-label="Checking owned DIDs" />;
    actions = <Button buttonRef={cancelRef} label="Cancel" variant="secondary" onPress={onClose} />;
  } else if (phase.kind === "choose") {
    const n = phase.dids.length;
    const phrase = deletePhrase(n);
    body = (
      <>
        <Text style={styles.body}>
          {n === 0
            ? `${did} will no longer be able to sign in or manage DIDs here.`
            : `${did} owns ${plural(n, "DID", "DIDs")}. Remove its access only — the DIDs stay hosted and still belong to it — or remove its access and delete them all. Deleting cannot be undone.`}
        </Text>
        {phase.listError && (
          <Text role="alert" style={styles.warning}>
            {phase.listError} If it owns DIDs, they will be kept.
          </Text>
        )}
        {n > 0 && <DidList dids={phase.dids} />}
        {n > 0 && (
          <Field
            label={`To delete the DIDs too, type ${phrase}`}
            value={typed}
            onChangeText={setTyped}
            autoCapitalize="none"
            autoCorrect={false}
            autoComplete="off"
            style={styles.typeField}
          />
        )}
      </>
    );
    actions = (
      <View style={styles.actions}>
        <Button buttonRef={cancelRef} label="Cancel" variant="secondary" onPress={onClose} />
        <Button
          label="Remove access only"
          variant={n > 0 ? "secondary" : "danger"}
          onPress={() => void accessOnly(phase.dids)}
        />
        {n > 0 && (
          <Button
            label={`Remove access and delete ${plural(n, "DID", "DIDs")}`}
            variant="danger"
            disabled={typed.trim() !== phrase}
            onPress={() => void deleteThenRemove(phase.dids)}
          />
        )}
      </View>
    );
  } else if (phase.kind === "running") {
    body = (
      <>
        <Text style={styles.body} aria-live="polite">
          {phase.step}
        </Text>
        {phase.dids.length > 0 && <DidList dids={phase.dids} status={phase.status} />}
      </>
    );
  } else {
    const failed = Object.keys(phase.errors).length;
    body = (
      <>
        <Text role="alert" style={styles.warning}>
          {failed > 0
            ? `${plural(failed, "DID", "DIDs")} could not be deleted, so ${did} keeps its access. The rest were deleted.`
            : `The access entry could not be removed: ${phase.aclError}`}
        </Text>
        {phase.dids.length > 0 && (
          <DidList dids={phase.dids} status={phase.status} errors={phase.errors} />
        )}
      </>
    );
    actions = (
      <View style={styles.actions}>
        <Button
          label="Close"
          variant="secondary"
          onPress={() => {
            void invalidateQueries(ACL_KEY, ["dids"]);
            onClose();
          }}
        />
        <Button
          label={failed > 0 ? "Retry the failed ones" : "Retry"}
          variant="danger"
          onPress={() =>
            failed > 0 || phase.dids.length > 0
              ? void deleteThenRemove(phase.dids, phase.status)
              : void accessOnly(phase.dids)
          }
        />
      </View>
    );
  }

  return (
    <Dialog
      visible
      title={`Remove access for this account?`}
      onClose={close}
      hideCloseButton={running}
      testID="remove-entry-dialog"
      actions={actions}
    >
      {body}
    </Dialog>
  );
}

const STATUS_LABEL: Record<DidStatus, string> = {
  pending: "waiting",
  deleting: "deleting…",
  deleted: "deleted",
  failed: "failed",
};

function DidList({
  dids,
  status,
  errors,
}: {
  dids: DidRecord[];
  status?: Record<string, DidStatus>;
  errors?: Record<string, string>;
}) {
  return (
    <ScrollView style={styles.list}>
      <View role="list" aria-label="DIDs owned by this account">
        {dids.map((d) => {
          const s = status?.[d.mnemonic];
          return (
            <View key={d.mnemonic} role="listitem" style={styles.listRow}>
              <Text style={styles.mono} numberOfLines={1}>
                {d.domain ? `${d.domain}/` : ""}
                {d.mnemonic}
              </Text>
              {s && (
                <Text
                  style={[
                    styles.status,
                    s === "deleted" && styles.ok,
                    s === "failed" && styles.bad,
                  ]}
                >
                  {STATUS_LABEL[s]}
                </Text>
              )}
              {errors?.[d.mnemonic] && <Text style={styles.rowError}>{errors[d.mnemonic]}</Text>}
            </View>
          );
        })}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  body: {
    fontFamily: fonts.regular,
    fontSize: 14,
    lineHeight: 20,
    color: colors.textSecondary,
  },
  warning: {
    fontFamily: fonts.medium,
    fontSize: 13,
    lineHeight: 18,
    color: colors.warning,
    marginTop: spacing.sm,
  },
  typeField: {
    marginTop: spacing.md,
    marginBottom: 0,
  },
  actions: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "flex-end",
    gap: spacing.sm,
  },
  list: {
    maxHeight: 220,
    marginTop: spacing.md,
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.sm,
    padding: spacing.sm,
  },
  listRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    gap: spacing.sm,
    paddingVertical: 2,
  },
  mono: {
    flexShrink: 1,
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.textPrimary,
  },
  status: {
    fontFamily: fonts.medium,
    fontSize: 12,
    color: colors.textTertiary,
  },
  ok: { color: colors.success },
  bad: { color: colors.error },
  rowError: {
    width: "100%",
    fontFamily: fonts.regular,
    fontSize: 12,
    color: colors.error,
  },
});
