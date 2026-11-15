import { StyleSheet, Text, View } from "react-native";
import { Link } from "expo-router";

import type { DidRecord } from "../lib/api";
import { compactDid } from "../lib/did-table";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { formatDate } from "../lib/time";
import { AgentNameChips, servedNames } from "./AgentNameChips";
import { CopyButton } from "./CopyButton";
import { DidQrButton } from "./DidQrButton";

/**
 * The DID list as cards, for a narrow window where the table would scroll
 * sideways and hide its columns. Same facts as a table row, stacked.
 */
export function DidCards({
  rows,
  search,
  myDid,
  markOwners,
  showMethod,
  showDomain,
}: {
  rows: DidRecord[];
  search: string;
  myDid: string | null;
  markOwners: boolean;
  showMethod: boolean;
  showDomain: boolean;
}) {
  if (rows.length === 0) {
    return <Text style={styles.hint}>No DIDs match “{search.trim()}”.</Text>;
  }
  return (
    <View role="list" aria-label="DIDs" style={styles.list}>
      {rows.map((item) => {
        const isOwn = item.owner === myDid;
        const names = servedNames(item.agentNames);
        return (
          <View key={item.mnemonic} role="listitem" style={styles.card}>
            <View style={styles.nameRow}>
              <Link href={`/dids/${item.mnemonic}`} style={styles.mnemonic}>
                {item.mnemonic}
              </Link>
              {showMethod && item.method && <Badge text={`did:${item.method}`} tone="teal" />}
              {markOwners && isOwn && <Badge text="You" tone="teal" />}
              {item.disabled && <Badge text="Suspended" tone="error" />}
            </View>
            {showDomain && item.domain ? <Text style={styles.sub}>{item.domain}</Text> : null}
            {names.length > 0 && (
              <View style={styles.gap}>
                <AgentNameChips
                  names={names}
                  domain={item.domain}
                  didId={item.didId}
                  size="sm"
                  showHost={false}
                />
              </View>
            )}
            {markOwners && !isOwn && (
              <Text style={styles.sub} numberOfLines={1}>
                Owner: {item.owner}
              </Text>
            )}
            <View style={[styles.didRow, styles.gap]}>
              {item.versionCount === 0 ? (
                <Text style={styles.pending}>Pending upload — waiting for its first did.jsonl</Text>
              ) : item.didId ? (
                <>
                  <Text style={styles.did} numberOfLines={1} aria-label={item.didId}>
                    {compactDid(item.didId)}
                  </Text>
                  <CopyButton
                    value={item.didId}
                    accessibilityLabel={`Copy DID of ${item.mnemonic}`}
                  />
                  <DidQrButton did={item.didId} label={item.mnemonic} />
                </>
              ) : (
                <Text style={styles.sub}>Uploaded</Text>
              )}
            </View>
            <Text style={[styles.meta, styles.gap]}>
              {item.versionCount.toLocaleString()}{" "}
              {item.versionCount === 1 ? "version" : "versions"} ·{" "}
              {item.totalResolves.toLocaleString()} resolves · created {formatDate(item.createdAt)}
              {item.versionCount > 1 ? ` · updated ${formatDate(item.updatedAt)}` : ""}
            </Text>
          </View>
        );
      })}
    </View>
  );
}

function Badge({ text, tone }: { text: string; tone: "teal" | "error" }) {
  return (
    <View style={[styles.badge, tone === "error" ? styles.badgeError : styles.badgeTeal]}>
      <Text style={[styles.badgeText, tone === "error" ? styles.textError : styles.textTeal]}>
        {text}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  list: {
    gap: spacing.sm,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.md,
  },
  nameRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    gap: spacing.xs,
  },
  mnemonic: {
    fontSize: 15,
    fontFamily: fonts.mono,
    fontWeight: "600",
    color: colors.accent,
  },
  sub: {
    marginTop: 2,
    fontSize: 12,
    fontFamily: fonts.mono,
    color: colors.textTertiary,
  },
  gap: {
    marginTop: spacing.xs,
  },
  didRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.xs,
  },
  did: {
    flexShrink: 1,
    fontSize: 12,
    fontFamily: fonts.mono,
    color: colors.success,
  },
  pending: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.warning,
  },
  meta: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  badge: {
    borderRadius: radii.sm,
    paddingVertical: 2,
    paddingHorizontal: spacing.sm,
  },
  badgeTeal: { backgroundColor: colors.tealMuted },
  badgeError: { backgroundColor: colors.errorBg },
  badgeText: { fontSize: 10, fontFamily: fonts.semibold },
  textTeal: { color: colors.teal },
  textError: { color: colors.error },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginTop: spacing.xl,
  },
});
