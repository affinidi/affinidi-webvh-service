import { useState } from "react";
import { StyleSheet, Text } from "react-native";

import { showConfirm } from "../../lib/alert";
import { errorMessage } from "../../lib/errors";
import { colors, spacing } from "../../lib/theme";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { didStyles } from "./styles";

/** Roll back the last log entry, or delete the DID. */
export function DangerZone({
  mnemonic,
  versionCount,
  logEntryCount,
  onRolledBack,
  onDeleted,
  notify,
}: {
  mnemonic: string;
  /** The record's version count, which `did/rollback` is state-checked against. */
  versionCount: number | null;
  logEntryCount: number;
  onRolledBack: () => void;
  onDeleted: () => void;
  notify: (title: string, message: string) => void;
}) {
  const api = useApi();
  const [rollingBack, setRollingBack] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const canRollBack = logEntryCount >= 2;

  const rollback = () => {
    showConfirm(
      "Rollback Last Entry",
      "Are you sure you want to remove the last log entry? This cannot be undone.",
      async () => {
        if (versionCount === null) return;
        setRollingBack(true);
        try {
          await api.rollbackDid(mnemonic, versionCount);
          onRolledBack();
          notify("Success", "Last log entry has been rolled back");
        } catch (e: unknown) {
          notify("Error", errorMessage(e, "Rollback failed"));
        } finally {
          setRollingBack(false);
        }
      },
    );
  };

  const remove = () => {
    showConfirm(
      "Delete DID",
      `Are you sure you want to delete "${mnemonic}"? This cannot be undone.`,
      async () => {
        setDeleting(true);
        try {
          await api.deleteDid(mnemonic);
          onDeleted();
        } catch (e: unknown) {
          notify("Error", errorMessage(e, "Delete failed"));
          setDeleting(false);
        }
      },
    );
  };

  return (
    <Card title="Danger Zone" style={[didStyles.card, styles.card]}>
      <Button
        variant="secondary"
        label="Rollback Last Entry"
        busy={rollingBack}
        busyLabel="Rolling back..."
        disabled={!canRollBack}
        onPress={rollback}
        style={styles.warning}
        textStyle={styles.warningText}
      />
      {!canRollBack && logEntryCount > 0 && (
        <Text style={[didStyles.hint, styles.note]}>
          Cannot rollback — only one log entry exists.
        </Text>
      )}
      <Button
        variant="danger"
        label="Delete DID"
        busy={deleting}
        busyLabel="Deleting..."
        onPress={remove}
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
