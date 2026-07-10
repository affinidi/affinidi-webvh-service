/**
 * Service badges — render what a DID document advertises.
 *
 * One mapping, used by the DID list, the Servers list, and the dashboard's
 * control-plane card, so a `TSPTransport` service reads the same everywhere.
 *
 * The badges are derived purely from the `service[].type` values in the DID
 * document (see `did_hosting_common::did::service_types_from_doc`). There is
 * deliberately no "VTA" badge: nothing in the vta-sdk templates or in
 * `build_did_document` emits a VTA service type. "VTA" is a provisioning
 * mode, not a service — the `#vta-didcomm` service *id* has type
 * `DIDCommMessaging` and therefore shows as the DIDComm badge.
 *
 * Anything we don't have a first-class badge for collapses into a single
 * `Other` chip, whose tooltip lists the raw type names.
 */
import { View, Text, StyleSheet } from "react-native";
import { colors, fonts, radii } from "../lib/theme";

/** Service `type` strings this codebase knows by name. */
export const SERVICE_TYPE_HOSTING = "WebVHHosting";
/** Legacy alias accepted on read only; never written. */
export const SERVICE_TYPE_HOSTING_LEGACY = "WebVHHostingService";
export const SERVICE_TYPE_TSP = "TSPTransport";
export const SERVICE_TYPE_DIDCOMM = "DIDCommMessaging";

export type BadgeKind = "hosting" | "tsp" | "didcomm" | "other";

const BADGE_LABELS: Record<BadgeKind, string> = {
  hosting: "Hosting",
  tsp: "TSP",
  didcomm: "DIDComm",
  other: "Other",
};

/** Colour per badge, so the transports stay visually distinct at a glance. */
const BADGE_COLORS: Record<BadgeKind, { bg: string; fg: string }> = {
  hosting: { bg: "rgba(59, 113, 255, 0.15)", fg: colors.accentHover },
  tsp: { bg: colors.tealMuted, fg: colors.teal },
  didcomm: { bg: "rgba(255, 181, 71, 0.15)", fg: colors.warning },
  other: { bg: colors.bgTertiary, fg: colors.textTertiary },
};

function kindOf(serviceType: string): BadgeKind {
  switch (serviceType) {
    case SERVICE_TYPE_HOSTING:
    case SERVICE_TYPE_HOSTING_LEGACY:
      return "hosting";
    case SERVICE_TYPE_TSP:
      return "tsp";
    case SERVICE_TYPE_DIDCOMM:
      return "didcomm";
    default:
      return "other";
  }
}

/**
 * Collapse raw service types into ordered, deduped badge kinds.
 *
 * Order is fixed (hosting, TSP, DIDComm, other) rather than document order,
 * so badges line up column-wise when scanning a list of DIDs. Every unknown
 * type folds into the single trailing `other` badge.
 */
export function badgeKinds(serviceTypes: string[]): BadgeKind[] {
  const kinds = new Set(serviceTypes.map(kindOf));
  const ordered: BadgeKind[] = ["hosting", "tsp", "didcomm", "other"];
  return ordered.filter((k) => kinds.has(k));
}

/** The raw type strings that folded into the `other` badge, for the tooltip. */
function otherTypes(serviceTypes: string[]): string[] {
  return serviceTypes.filter((t) => kindOf(t) === "other");
}

export function ServiceBadge({
  kind,
  title,
}: {
  kind: BadgeKind;
  title?: string;
}) {
  const { bg, fg } = BADGE_COLORS[kind];
  return (
    <View style={[styles.badge, { backgroundColor: bg }]}>
      {/* `title` renders as a native tooltip on react-native-web. */}
      <Text style={[styles.badgeText, { color: fg }]} {...({ title } as any)}>
        {BADGE_LABELS[kind]}
      </Text>
    </View>
  );
}

/**
 * A row of badges for a DID document's advertised services.
 *
 * `services === undefined` means "not known" (no document yet, or a legacy
 * record M-02 hasn't swept) — renders nothing. `services === []` means the
 * document was read and advertises nothing; that renders the `emptyLabel`
 * if one is given, else nothing. The two cases look the same by default but
 * callers that care can distinguish them.
 */
export function ServiceBadges({
  services,
  emptyLabel,
}: {
  services?: string[];
  emptyLabel?: string;
}) {
  if (!services) return null;
  if (services.length === 0) {
    return emptyLabel ? (
      <Text style={styles.emptyText}>{emptyLabel}</Text>
    ) : null;
  }

  const kinds = badgeKinds(services);
  const others = otherTypes(services);

  return (
    <View style={styles.row}>
      {kinds.map((k) => (
        <ServiceBadge
          key={k}
          kind={k}
          title={k === "other" ? others.join(", ") : undefined}
        />
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 4,
    alignItems: "center",
  },
  badge: {
    borderRadius: radii.full,
    paddingHorizontal: 7,
    paddingVertical: 2,
  },
  badgeText: {
    fontSize: 10,
    fontFamily: fonts.bold,
    textTransform: "uppercase",
    letterSpacing: 0.4,
  },
  emptyText: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    fontStyle: "italic",
  },
});
