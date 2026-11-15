import { useState, type ChangeEvent, type ReactNode } from "react";
import { StyleSheet, Text, View } from "react-native";

import type { DidDocumentState, LogEntryInfo } from "../../lib/api";
import { notify } from "../../lib/feedback";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { Button } from "../Button";
import { Card } from "../Card";
import { Field } from "../Field";
import { didStyles } from "./styles";

const pretty = (state: DidDocumentState | null | undefined) =>
  state ? JSON.stringify(state, null, 2) : "";

/**
 * The DID document at any log version, and — with a connected agent wallet —
 * an editor whose result the agent publishes.
 *
 * We propose the new document; the VTA dry-runs its own update handler against
 * the authoritative log to work out what the edit would actually do —
 * including the update-key rotation any document change causes, which is
 * nowhere in what we send — and decides, per the user's policy, whether a
 * human has to approve it.
 */
export function DidDocumentCard({
  logEntries,
  selectedVersion,
  onSelectVersion,
  editing,
  onEditingChange,
  canPublish,
  publishing,
  onPublish,
  delegationWarning,
  consentPanel,
}: {
  logEntries: LogEntryInfo[];
  selectedVersion: number;
  onSelectVersion: (index: number) => void;
  editing: boolean;
  onEditingChange: (editing: boolean) => void;
  /** A connected wallet can relay a delegated publish. Without one there is
   *  no way to sign an edit from here, so the editor is not offered. */
  canPublish: boolean;
  publishing: boolean;
  onPublish: (document: Record<string, unknown>) => void;
  delegationWarning: string | null;
  /** The approval code, while a publish waits on the user. */
  consentPanel: ReactNode;
}) {
  const [draft, setDraft] = useState("");
  const selected = logEntries[selectedVersion]?.state;

  const toggleEdit = () => {
    if (!editing && selected) setDraft(pretty(selected));
    onEditingChange(!editing);
  };

  const selectVersion = (e: ChangeEvent<HTMLSelectElement>) => {
    const v = Number(e.target.value);
    onSelectVersion(v);
    const state = logEntries[v]?.state;
    if (editing && state) setDraft(pretty(state));
  };

  const publish = () => {
    let document: Record<string, unknown>;
    try {
      document = JSON.parse(draft) as Record<string, unknown>;
    } catch {
      notify("error", "Not published", "The document is not valid JSON.");
      return;
    }
    onPublish(document);
  };

  return (
    <Card
      title="DID Document"
      style={didStyles.card}
      headerRight={
        canPublish ? (
          <Button
            size="sm"
            variant="secondary"
            label={editing ? "Cancel" : "Edit"}
            accessibilityLabel={editing ? "Cancel editing the document" : "Edit the document"}
            onPress={toggleEdit}
          />
        ) : undefined
      }
    >
      {!canPublish && (
        <Text style={didStyles.hint}>
          Changes to this document must be signed by the DID&apos;s agent, which holds its update
          key. Connect a wallet that can relay to your agent to edit it here, or have the agent
          publish a new version and upload the signed did.jsonl below.
        </Text>
      )}
      <View style={styles.versionRow}>
        <Text style={didStyles.label}>Version</Text>
        <View style={styles.selectWrapper}>
          <select
            aria-label="Log version to show"
            value={selectedVersion}
            onChange={selectVersion}
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
      {editing && canPublish ? (
        <>
          <Field
            label="DID document (JSON)"
            hideLabel
            value={draft}
            onChangeText={setDraft}
            multiline
            inputStyle={[didStyles.textarea, styles.editor]}
          />
          <View style={didStyles.stack}>
            <Button
              label="Publish with my agent"
              busy={publishing}
              busyLabel="Asking your agent..."
              onPress={publish}
            />
            <Text style={didStyles.hint}>
              Your agent holds this DID&apos;s update key. It will work out what this change
              actually does before it signs anything — including effects that are not visible in the
              document above.
            </Text>
            {/*
                Shown, not enforced. An admin sees every DID on this server, so
                the button used to be offered on DIDs no agent of theirs could
                sign for — but the page cannot identify which agent the wallet
                holds, so a hard gate would also block the legitimate case
                (passkey session, wallet connected to the owning agent). Say
                what is odd and let the operator decide.
              */}
            {delegationWarning && (
              <Text style={[didStyles.hint, didStyles.warning]}>{delegationWarning}</Text>
            )}
          </View>
          {consentPanel}
        </>
      ) : (
        selected && (
          <div
            style={{
              backgroundColor: colors.bgPrimary,
              border: `1px solid ${colors.border}`,
              borderRadius: radii.sm,
              overflow: "auto",
              maxHeight: 500,
              padding: spacing.md,
            }}
          >
            <pre
              style={{
                margin: 0,
                fontFamily: fonts.mono,
                fontSize: 12,
                lineHeight: "18px",
                color: colors.textPrimary,
                whiteSpace: "pre",
              }}
            >
              {pretty(selected)}
            </pre>
          </div>
        )
      )}
    </Card>
  );
}

const styles = StyleSheet.create({
  versionRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    marginBottom: spacing.md,
  },
  selectWrapper: {
    flex: 1,
  },
  editor: {
    minHeight: 300,
  },
});
