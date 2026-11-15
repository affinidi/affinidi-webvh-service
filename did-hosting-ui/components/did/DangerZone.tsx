import { useState } from "react";
import { StyleSheet, Text } from "react-native";

import { errorMessage } from "../../lib/errors";
import { confirm, notify } from "../../lib/feedback";
import { colors, spacing } from "../../lib/theme";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { didStyles } from "./styles";

/** Suspend or resume, roll back the last log entry, or delete the DID. */
export function DangerZone({
  mnemonic,
  versionCount,
  logEntryCount,
  suspended,
  onRolledBack,
  onStateChanged,
  onDeleted,
}: {
  mnemonic: string;
  /** The record's version count, which `did/rollback` is state-checked against. */
  versionCount: number | null;
  logEntryCount: number;
  /** Whether the DID is suspended now; `null` while unknown. */
  suspended: boolean | null;
  onRolledBack: () => void;
  onStateChanged: () => void;
  onDeleted: () => void;
}) {
  const api = useApi();
  const [rollingBack, setRollingBack] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [switching, setSwitching] = useState(false);
  const canRollBack = logEntryCount >= 2;

  const rollback = async () => {
    if (versionCount === null) return;
    const ok = await confirm({
      title: "Roll back the last entry?",
      body:
        `Version ${versionCount} of "${mnemonic}" is removed and resolvers get version ` +
        `${versionCount - 1} again. This cannot be undone; to restore it, the DID's agent must ` +
        `publish it again.`,
      confirmLabel: "Roll back",
    });
    if (!ok) return;
    setRollingBack(true);
    try {
      await api.rollbackDid(mnemonic, versionCount);
      onRolledBack();
      notify("success", "Rolled back", `"${mnemonic}" is at version ${versionCount - 1} again.`);
    } catch (e: unknown) {
      notify("error", "Could not roll back", errorMessage(e, "Rollback failed"));
    } finally {
      setRollingBack(false);
    }
  };

  const setState = async (next: "active" | "suspended") => {
    if (next === "suspended") {
      const ok = await confirm({
        title: `Suspend "${mnemonic}"?`,
        body:
          "Resolvers get a deactivated document until you resume it. The log is kept, so " +
          "resuming restores it exactly. A suspension made by an administrator can only be " +
          "lifted by an administrator.",
        confirmLabel: "Suspend DID",
      });
      if (!ok) return;
    }
    setSwitching(true);
    try {
      await api.setDidState(mnemonic, next);
      onStateChanged();
      notify(
        "success",
        next === "suspended" ? "DID suspended" : "DID resumed",
        next === "suspended"
          ? `"${mnemonic}" no longer resolves.`
          : `"${mnemonic}" resolves normally again.`,
      );
    } catch (e: unknown) {
      notify(
        "error",
        next === "suspended" ? "Could not suspend the DID" : "Could not resume the DID",
        errorMessage(e),
      );
    } finally {
      setSwitching(false);
    }
  };

  const remove = async () => {
    const ok = await confirm({
      title: `Delete "${mnemonic}"?`,
      body:
        "The DID and its whole log are deleted from the control plane and every hosting " +
        "server, and the path becomes free for anyone to register. Resolvers will no longer " +
        "find it. This cannot be undone.",
      confirmLabel: "Delete DID",
      typeToConfirm: mnemonic,
    });
    if (!ok) return;
    setDeleting(true);
    try {
      await api.deleteDid(mnemonic);
      notify("success", "DID deleted", `"${mnemonic}" has been deleted.`);
      onDeleted();
    } catch (e: unknown) {
      notify("error", "Could not delete the DID", errorMessage(e, "Delete failed"));
      setDeleting(false);
    }
  };

  return (
    <Card title="Danger Zone" style={[didStyles.card, styles.card]}>
      {suspended !== null && (
        <>
          <Button
            variant="secondary"
            label={suspended ? "Resume DID" : "Suspend DID"}
            busy={switching}
            busyLabel={suspended ? "Resuming…" : "Suspending…"}
            onPress={() => void setState(suspended ? "active" : "suspended")}
            style={styles.warning}
            textStyle={styles.warningText}
          />
          <Text style={[didStyles.hint, styles.note]}>
            {suspended
              ? "Suspended: resolvers get a deactivated document. Resuming restores the log as it was."
              : "Suspending stops it resolving without deleting anything."}
          </Text>
        </>
      )}
      <Button
        variant="secondary"
        label="Roll Back Last Entry"
        busy={rollingBack}
        busyLabel="Rolling back..."
        disabled={!canRollBack}
        onPress={() => void rollback()}
        style={[styles.warning, suspended !== null && styles.gap]}
        textStyle={styles.warningText}
      />
      {!canRollBack && logEntryCount > 0 && (
        <Text style={[didStyles.hint, styles.note]}>
          Cannot roll back — only one log entry exists.
        </Text>
      )}
      <Button
        variant="danger"
        label="Delete DID"
        busy={deleting}
        busyLabel="Deleting..."
        onPress={() => void remove()}
        style={styles.gap}
      />
    </Card>
  );
}

const styles = StyleSheet.create({
  card: {
    borderColor: "rgba(255, 92, 92, 0.25)",
  },
  warning: {
    backgroundColor: "transparent",
    borderColor: colors.warning,
  },
  warningText: {
    color: colors.warning,
  },
  note: {
    marginTop: spacing.xs,
    marginBottom: 0,
  },
  gap: {
    marginTop: spacing.md,
  },
});
