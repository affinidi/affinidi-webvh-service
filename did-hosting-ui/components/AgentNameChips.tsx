/**
 * Agent name chips — the human-memorable handles that redirect to a DID.
 *
 * An agent name is `webvh.storm.ws/@alice`: a name on a hosting domain that
 * `GET /@alice` 302s to the DID. It is an *alias*, not an identifier, which is
 * what drives the placement decision everywhere this is used — the DID stays
 * the primary line and the name sits under it, never in place of it. Two
 * near-identical friendly labels stacked above the thing they both point at is
 * how a reader loses track of which string is authoritative.
 *
 * Rendered identically on the DID list and the DID detail page (only the
 * density differs) so a handle is recognisable in both without re-reading it.
 *
 * ## What gets copied
 *
 * The chip copies exactly what it shows — `webvh.storm.ws/@alice`, the form
 * the agent-name FAQ writes names in and the one `AgentName::parse` accepts.
 * A copy button that yields a different string than the one on screen is the
 * kind of small surprise that makes people paste twice to check.
 */
import { useState } from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";
import * as Clipboard from "expo-clipboard";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { extractDidHost } from "../lib/domain";

/**
 * The hosting domain a name is scoped to.
 *
 * Prefers the record's persisted `domain`, falling back to the DID
 * identifier's host — the same order `matchesDomain` uses, and for the same
 * reason: legacy slots the M-01 sweep hasn't backfilled still carry an empty
 * `domain` while their DID string has always held the authority.
 */
export function agentNameHost(
  domain: string | undefined | null,
  didId: string | undefined | null,
): string | null {
  return domain || extractDidHost(didId);
}

/** The canonical display (and copy) form: `webvh.storm.ws/@alice`. */
export function formatAgentName(host: string, name: string): string {
  return `${host}/@${name}`;
}

export function AgentNameChips({
  names,
  domain,
  didId,
  size = "md",
}: {
  /** Local parts only (`alice`), as the API returns them. */
  names?: string[];
  domain?: string | null;
  didId?: string | null;
  /** `sm` for list rows, `md` for the detail header. */
  size?: "sm" | "md";
}) {
  const [copied, setCopied] = useState<string | null>(null);

  const host = agentNameHost(domain, didId);
  // No names is the common case — every DID on a deployment that hasn't
  // enabled the feature. Render nothing rather than an empty label so those
  // rows look exactly as they did before agent names existed.
  if (!names || names.length === 0 || !host) return null;

  const handleCopy = async (value: string) => {
    await Clipboard.setStringAsync(value);
    setCopied(value);
    setTimeout(() => setCopied(null), 2000);
  };

  const small = size === "sm";

  return (
    <View style={styles.row}>
      {names.map((name) => {
        const full = formatAgentName(host, name);
        return (
          <View
            key={name}
            style={[styles.chip, small ? styles.chipSm : styles.chipMd]}
          >
            <Text
              style={[styles.chipText, small && styles.chipTextSm]}
              numberOfLines={1}
            >
              {/* The `@` carries the meaning; give it the accent so the eye
                  finds the handle without reading the domain first. */}
              <Text style={styles.chipHost}>{host}/</Text>
              <Text style={styles.chipAt}>@</Text>
              {name}
            </Text>
            <Pressable
              style={styles.copyButton}
              accessibilityLabel={`Copy agent name ${full}`}
              onPress={(e) => {
                // Chips live inside a pressable card on the list view; without
                // this the copy would also navigate into the DID.
                e.preventDefault();
                e.stopPropagation?.();
                void handleCopy(full);
              }}
            >
              <Text style={styles.copyButtonText}>
                {copied === full ? "Copied" : "Copy"}
              </Text>
            </Pressable>
          </View>
        );
      })}
    </View>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    gap: spacing.sm,
  },
  chip: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    borderRadius: radii.full,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.tealMuted,
  },
  chipSm: {
    paddingVertical: 2,
    paddingHorizontal: spacing.sm,
  },
  chipMd: {
    paddingVertical: 4,
    paddingHorizontal: spacing.md,
  },
  chipText: {
    fontFamily: fonts.mono,
    fontSize: 13,
    color: colors.teal,
    flexShrink: 1,
  },
  chipTextSm: {
    fontSize: 12,
  },
  chipHost: {
    color: colors.textTertiary,
  },
  chipAt: {
    fontFamily: fonts.bold,
    color: colors.teal,
  },
  copyButton: {
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.sm,
    paddingVertical: 1,
    paddingHorizontal: spacing.sm,
  },
  copyButtonText: {
    fontSize: 10,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
  },
});
