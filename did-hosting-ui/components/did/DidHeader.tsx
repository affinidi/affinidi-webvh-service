import { StyleSheet, Text, View } from "react-native";

import type { DidDetailResponse } from "../../lib/api";
import { colors, fonts, spacing } from "../../lib/theme";
import { AgentNameChips } from "../AgentNameChips";
import { CopyButton } from "../CopyButton";
import { Heading } from "../Heading";

/**
 * The page title, the DID and every other address it answers to, and its
 * owner.
 */
export function DidHeader({
  mnemonic,
  detail,
  scidAliases,
  boundNames,
  agentDomain,
  ownerNames,
}: {
  mnemonic: string;
  detail: DidDetailResponse | null;
  /** did:scid forms the live document lists for itself. */
  scidAliases: string[];
  /** Names the live document claims (local parts). */
  boundNames: string[];
  agentDomain: string | null;
  /** The owner's own served names, if this service hosts the owner too. */
  ownerNames: string[];
}) {
  return (
    <View>
      <Heading level={1} style={styles.title}>
        {mnemonic === ".well-known" ? "Root DID (.well-known)" : mnemonic}
      </Heading>

      {detail &&
        (detail.didId ? (
          <View style={[styles.didIdRow, boundNames.length > 0 && styles.didIdRowTight]}>
            <Text style={styles.didIdText} numberOfLines={1} selectable>
              {detail.didId}
            </Text>
            <CopyButton value={detail.didId} accessibilityLabel={`Copy DID ${detail.didId}`} />
          </View>
        ) : (
          <Text style={styles.pendingText}>Pending upload</Text>
        ))}
      {scidAliases.map((alias) => (
        <View key={alias} style={styles.didIdRow}>
          <Text style={styles.didIdText} numberOfLines={1} selectable>
            {alias}
          </Text>
          <CopyButton value={alias} accessibilityLabel={`Copy did:scid alias ${alias}`} />
        </View>
      ))}
      {/* Agent names, directly under the DID they redirect to.

          Copy-only here; binding and parking stay in the Agent Names card
          below. The card is where you *manage* names, but it sits under the
          document viewer — too far to reach for the everyday act of copying
          a handle to give someone, which is what this line is for.

          `boundNames` (not the registry) so this never contradicts the card
          below — both show what the live document claims.

          The DID row tightens its bottom margin only when names follow, so a
          DID with no names keeps exactly the spacing it has today. */}
      {boundNames.length > 0 && (
        <View style={styles.agentNamesRow}>
          <AgentNameChips names={boundNames} domain={agentDomain} didId={detail?.didId} />
        </View>
      )}
      {/* Owner. The owner is a DID like any other — usually the VTA that
          registered this slot — so if it is hosted here and serves a name,
          show the handle under it. */}
      {detail && (
        <View style={styles.ownerRow}>
          <Text style={styles.ownerText}>Owner: {detail.owner}</Text>
          {ownerNames.length > 0 && (
            <AgentNameChips names={ownerNames} didId={detail.owner} size="sm" />
          )}
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  title: {
    fontSize: 20,
    fontFamily: fonts.mono,
    // `accentHover`, not `accent`: the title is text on the page background,
    // and the lighter blue keeps it above 4.5:1.
    color: colors.accentHover,
    marginBottom: spacing.sm,
  },
  didIdRow: {
    flexDirection: "row",
    alignItems: "center",
    alignSelf: "flex-start",
    gap: spacing.sm,
    marginBottom: spacing.xl,
  },
  didIdRowTight: {
    marginBottom: spacing.sm,
  },
  agentNamesRow: {
    alignSelf: "flex-start",
    marginBottom: spacing.xl,
  },
  didIdText: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.teal,
    flexShrink: 1,
  },
  pendingText: {
    fontSize: 14,
    fontFamily: fonts.medium,
    color: colors.warning,
    marginBottom: spacing.xl,
  },
  ownerRow: {
    flexDirection: "row",
    alignItems: "center",
    flexWrap: "wrap",
    gap: spacing.sm,
    marginBottom: spacing.lg,
  },
  ownerText: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textSecondary,
  },
});
