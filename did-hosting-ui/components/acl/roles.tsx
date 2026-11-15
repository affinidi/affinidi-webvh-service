import { StyleSheet, Text, View } from "react-native";

import type { Role } from "../../lib/api";
import type { SegmentOption } from "../SegmentedControl";
import { colors, fonts } from "../../lib/theme";

/** Human-readable role label. The wire value `metricsReader` is a single
 *  lowercase token, so naive capitalisation renders "Metricsreader"; spell it
 *  "Metrics Reader" and capitalise the rest. */
export const roleLabel = (r: string): string =>
  r === "metricsReader" ? "Metrics Reader" : r.charAt(0).toUpperCase() + r.slice(1);

const option = <R extends Role>(r: R): SegmentOption<R> => ({ value: r, label: roleLabel(r) });

/** What each role may do, in a line — shown under the role picker. */
export const ROLE_DESCRIPTIONS: Record<Role, string> = {
  owner: "Creates and manages their own DIDs, within the domains and quotas set here.",
  admin: "Manages everything: every DID, domain, server and access entry.",
  service:
    "A machine account for a hosting server: registers with the control plane and reports its statistics. It cannot manage DIDs or access.",
  metricsReader: "Reads the service's metrics counters only; cannot see or change DIDs.",
};

/** Every role an ACL entry can hold, in picker order. */
export const ENTRY_ROLES: readonly SegmentOption<Role>[] = [
  option("owner"),
  option("admin"),
  option("service"),
  option("metricsReader"),
];

/** The roles a sign-in invite can grant. */
export type InviteRole = "admin" | "owner" | "service";
export const INVITE_ROLES: readonly SegmentOption<InviteRole>[] = [
  option("owner"),
  option("admin"),
  option("service"),
];

/** A role badge. The role is written out, so it never rests on colour. */
export function RoleBadge({ role, text }: { role: Role; text?: string }) {
  return (
    <View
      style={[styles.badge, role === "admin" && styles.admin, role === "service" && styles.service]}
    >
      <Text style={styles.text}>{text ?? role}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    backgroundColor: colors.tealMuted,
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  admin: {
    backgroundColor: "rgba(59, 113, 255, 0.15)",
  },
  service: {
    backgroundColor: "rgba(168, 85, 247, 0.15)",
  },
  text: {
    fontSize: 11,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    textTransform: "uppercase",
  },
});
