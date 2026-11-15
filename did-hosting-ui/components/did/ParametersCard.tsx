import { StyleSheet, Text, View } from "react-native";

import type { LogEntryInfo } from "../../lib/api";
import { spacing } from "../../lib/theme";
import { Card } from "../Card";
import { ChipInput } from "../ChipInput";
import { CopyButton } from "../CopyButton";
import { alsoKnownAsOf } from "./agent-names";
import { didStyles } from "./styles";
import { Term } from "../Term";

/** Witness DIDs out of an unchecked `witness` parameter. */
function witnessIdsOf(witness: unknown): string[] {
  const list = (witness as { witnesses?: unknown } | null | undefined)?.witnesses;
  if (!Array.isArray(list)) return [];
  return list
    .map((w: unknown) => (w && typeof w === "object" ? (w as { id?: unknown }).id : null))
    .filter((id: unknown): id is string => typeof id === "string");
}

function stringsOf(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((w: unknown): w is string => typeof w === "string") : [];
}

/**
 * The latest log entry's parameters, read-only.
 *
 * Parameters change only in a new signed log entry, which the DID's agent
 * produces; nothing typed here could be sent anywhere. So the card shows them
 * and offers them as JSON to copy into whatever builds the next entry.
 */
export function ParametersCard({
  latest,
  knownWatcherUrls,
}: {
  /** The newest log entry. */
  latest: LogEntryInfo | undefined;
  /** Watcher URLs this DID's domain is configured with, shown for reference. */
  knownWatcherUrls: string[];
}) {
  const params = latest?.parameters ?? {};
  const watchers = stringsOf(params.watchers);
  const witnesses = witnessIdsOf(params.witness);
  const alsoKnownAs = latest?.state ? alsoKnownAsOf(latest.state.alsoKnownAs) : [];
  const portable = params.portable === true;
  const ttl = typeof params.ttl === "number" ? params.ttl : null;
  const missingWatchers = knownWatcherUrls.filter((w) => !watchers.includes(w));

  return (
    <Card
      title="Parameters"
      style={didStyles.card}
      headerRight={
        <CopyButton
          value={JSON.stringify(params, null, 2)}
          label="Copy parameters JSON"
          accessibilityLabel="Copy the latest entry's parameters as JSON"
          variant="secondary"
          size="sm"
        />
      }
    >
      <Text style={didStyles.hint}>
        The parameters of the latest log entry. They change only when the DID&apos;s agent publishes
        a new signed entry; copy them as a starting point for it.
      </Text>

      <View style={styles.field}>
        <Term term="watcher" label="Watchers" style={didStyles.caption} />
        <ChipInput label="Watchers" values={watchers} onChange={noop} readOnly />
        {missingWatchers.length > 0 && (
          <Text style={didStyles.hint}>
            This DID&apos;s domain also offers: {missingWatchers.join(", ")}
          </Text>
        )}
      </View>

      <View style={styles.field}>
        <Term term="witness" label="Witnesses" style={didStyles.caption} />
        <ChipInput label="Witnesses" values={witnesses} onChange={noop} readOnly />
      </View>

      <View style={styles.field}>
        <Term term="alsoKnownAs" label="Also Known As" style={didStyles.caption} />
        <ChipInput label="Also Known As" values={alsoKnownAs} onChange={noop} readOnly />
      </View>

      <View style={[styles.field, styles.inline]}>
        <Term
          term="portable"
          label={`Portable: ${portable ? "yes" : "no"}`}
          style={didStyles.caption}
        />
        <Term
          term="ttl"
          label={`Cache time (TTL): ${ttl === null ? "default" : `${ttl.toLocaleString()} s`}`}
          style={didStyles.caption}
        />
      </View>
    </Card>
  );
}

const noop = () => {};

const styles = StyleSheet.create({
  field: {
    marginBottom: spacing.md,
  },
  inline: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    gap: spacing.lg,
  },
});
