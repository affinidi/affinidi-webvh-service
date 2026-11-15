import { useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";

import type { LogEntryInfo } from "../../lib/api";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { Button } from "../Button";
import { Card } from "../Card";
import { ChipInput } from "../ChipInput";
import { alsoKnownAsOf } from "./agent-names";
import { didStyles } from "./styles";

/** Witness DIDs out of an unchecked `witness` parameter. */
function witnessIdsOf(witness: unknown): string[] {
  const list = (witness as { witnesses?: unknown } | null | undefined)?.witnesses;
  if (!Array.isArray(list)) return [];
  return list
    .map((w: unknown) => (w && typeof w === "object" ? (w as { id?: unknown }).id : null))
    .filter((id: unknown): id is string => typeof id === "string");
}

/**
 * The latest entry's parameters, editable as a scratch pad for the next log
 * entry. Informational: nothing here is sent anywhere — the values are for
 * constructing signed JSONL.
 */
export function ParametersCard({
  latest,
  knownWatcherUrls,
}: {
  /** The newest log entry; the editor resets to it whenever it changes. */
  latest: LogEntryInfo | undefined;
  /** Watcher URLs to suggest: the ones this DID's domain is configured with. */
  knownWatcherUrls: string[];
}) {
  const [editing, setEditing] = useState(false);
  const [watchers, setWatchers] = useState<string[]>([]);
  const [witnesses, setWitnesses] = useState<string[]>([]);
  const [alsoKnownAs, setAlsoKnownAs] = useState<string[]>([]);
  const [portable, setPortable] = useState(false);
  const [ttl, setTtl] = useState("");

  // Sync the editor when the log changes.
  useEffect(() => {
    if (!latest) return;
    const params = latest.parameters;
    if (params) {
      setPortable(params.portable === true);
      setTtl(typeof params.ttl === "number" ? String(params.ttl) : "");
      setWatchers(
        Array.isArray(params.watchers)
          ? params.watchers.filter((w: unknown): w is string => typeof w === "string")
          : [],
      );
      setWitnesses(witnessIdsOf(params.witness));
    }
    if (latest.state) setAlsoKnownAs(alsoKnownAsOf(latest.state.alsoKnownAs));
  }, [latest]);

  return (
    <Card
      title="Parameters"
      style={didStyles.card}
      headerRight={
        <Button
          size="sm"
          variant="secondary"
          label={editing ? "Done" : "Edit Parameters"}
          pressed={editing}
          onPress={() => setEditing(!editing)}
        />
      }
    >
      {!editing && (
        <Text style={didStyles.hint}>
          View and configure parameters for the next log entry. Editing is informational — use these
          values when constructing signed JSONL.
        </Text>
      )}

      <View style={styles.field}>
        <Text style={didStyles.caption}>Watchers</Text>
        <ChipInput
          label="Watchers"
          values={watchers}
          onChange={setWatchers}
          suggestions={knownWatcherUrls}
          placeholder="Add watcher URL..."
          readOnly={!editing}
        />
      </View>

      <View style={styles.field}>
        <Text style={didStyles.caption}>Witnesses</Text>
        <ChipInput
          label="Witnesses"
          values={witnesses}
          onChange={setWitnesses}
          placeholder="Add witness DID..."
          readOnly={!editing}
        />
      </View>

      <View style={styles.field}>
        <Text style={didStyles.caption}>Also Known As</Text>
        <ChipInput
          label="Also Known As"
          values={alsoKnownAs}
          onChange={setAlsoKnownAs}
          placeholder="Add alternate identifier..."
          readOnly={!editing}
        />
      </View>

      <View style={[styles.field, styles.inline]}>
        <View style={didStyles.row}>
          <Text style={didStyles.caption}>Portable</Text>
          <input
            type="checkbox"
            aria-label="Portable"
            checked={portable}
            onChange={(e) => setPortable(e.target.checked)}
            disabled={!editing}
            style={{ accentColor: colors.accent }}
          />
        </View>
        <View style={didStyles.row}>
          <Text style={didStyles.caption}>TTL</Text>
          <input
            type="number"
            aria-label="TTL in seconds"
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            disabled={!editing}
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
    </Card>
  );
}

const styles = StyleSheet.create({
  field: {
    marginBottom: spacing.md,
  },
  inline: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.lg,
  },
});
