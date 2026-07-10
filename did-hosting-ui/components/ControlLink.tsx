/**
 * Control-plane link: the transport that **actually carried** traffic to and
 * from a registered service, per direction.
 *
 * Deliberately not derived from `advertisedServices`. What a DID document
 * advertises is what a peer *can* speak; this is what moved. They disagree
 * whenever a TSP send falls back to DIDComm, or a server registered over
 * DIDComm before its document advertised anything. Showing the advertised
 * value here would quietly tell the operator the wrong thing.
 *
 * `in` is the last message received from the service (registration, health
 * pong). `out` is the last health ping sent to it — scoped to the ping because
 * it is the only outbound path on a timer, so it is the only one whose
 * observation stays fresh.
 */
import { View, Text, StyleSheet } from "react-native";
import { colors, fonts, radii } from "../lib/theme";
import type { ObservedTransport } from "../lib/api";

const TRANSPORT_LABELS: Record<ObservedTransport, string> = {
  tsp: "TSP",
  didcomm: "DIDComm",
  https: "HTTPS",
};

const TRANSPORT_COLORS: Record<ObservedTransport, { bg: string; fg: string }> = {
  tsp: { bg: colors.tealMuted, fg: colors.teal },
  didcomm: { bg: "rgba(255, 181, 71, 0.15)", fg: colors.warning },
  https: { bg: "rgba(59, 113, 255, 0.15)", fg: colors.accentHover },
};

function timeAgo(epoch?: number): string | null {
  if (!epoch) return null;
  const secs = Math.floor(Date.now() / 1000) - epoch;
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function Direction({
  arrow,
  label,
  transport,
  at,
}: {
  arrow: string;
  label: string;
  transport?: ObservedTransport;
  at?: number;
}) {
  const when = timeAgo(at);
  return (
    <View style={styles.row}>
      <Text style={styles.arrow}>{arrow}</Text>
      <Text style={styles.dirLabel}>{label}</Text>
      {transport ? (
        <View
          style={[
            styles.chip,
            { backgroundColor: TRANSPORT_COLORS[transport].bg },
          ]}
        >
          <Text style={[styles.chipText, { color: TRANSPORT_COLORS[transport].fg }]}>
            {TRANSPORT_LABELS[transport]}
          </Text>
        </View>
      ) : (
        <Text style={styles.none}>nothing observed yet</Text>
      )}
      {when && <Text style={styles.when}>{when}</Text>}
    </View>
  );
}

export function ControlLink({
  lastInboundTransport,
  lastInboundAt,
  lastOutboundTransport,
  lastOutboundAt,
  trustTaskCapable,
}: {
  lastInboundTransport?: ObservedTransport;
  lastInboundAt?: number;
  lastOutboundTransport?: ObservedTransport;
  lastOutboundAt?: number;
  trustTaskCapable?: boolean;
}) {
  return (
    <View style={styles.block}>
      <Text style={styles.heading}>Control link</Text>
      <Direction
        arrow="↓"
        label="in"
        transport={lastInboundTransport}
        at={lastInboundAt}
      />
      <Direction
        arrow="↑"
        label="out"
        transport={lastOutboundTransport}
        at={lastOutboundAt}
      />
      {trustTaskCapable === false && (
        <Text style={styles.legacyNote}>
          Legacy messaging — this server predates trust tasks, so it is
          always pinged over DIDComm regardless of what its DID document
          advertises.
        </Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  block: {
    marginTop: 8,
    gap: 3,
  },
  heading: {
    fontSize: 11,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.5,
    marginBottom: 2,
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    flexWrap: "wrap",
  },
  arrow: {
    fontSize: 12,
    color: colors.textTertiary,
    width: 12,
  },
  dirLabel: {
    fontSize: 11,
    fontFamily: fonts.mono,
    color: colors.textTertiary,
    width: 26,
  },
  chip: {
    borderRadius: radii.full,
    paddingHorizontal: 7,
    paddingVertical: 1,
  },
  chipText: {
    fontSize: 10,
    fontFamily: fonts.bold,
    textTransform: "uppercase",
    letterSpacing: 0.4,
  },
  none: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    fontStyle: "italic",
  },
  when: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  legacyNote: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    lineHeight: 16,
    marginTop: 2,
  },
});
