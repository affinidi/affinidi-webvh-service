import { useId, useState } from "react";
import { Pressable, StyleSheet, Text, View, type StyleProp, type TextStyle } from "react-native";

import { webAria } from "../lib/a11y";
import { colors, focusRing, fonts, radii, spacing } from "../lib/theme";

/**
 * One-line explanations of the protocol words the console cannot avoid.
 * Kept here, in one place, so every screen explains a term the same way.
 */
export const GLOSSARY = {
  path: "The part of the DID's address after the domain — for example people/alice in did:webvh:…:example.com:people:alice. Also called the DID's name or mnemonic.",
  scid: "Self-certifying identifier: the hash in a did:webvh that is derived from the DID's first log entry, so the DID can't be swapped for another one.",
  witness:
    "A third party that must co-sign each new version of the DID before it is accepted, so the controller can't quietly rewrite history.",
  watcher:
    "A service that keeps its own copy of the DID's log and can raise the alarm if the hosted copy changes unexpectedly.",
  portable:
    "Whether the DID may later move to a different domain while keeping its identity (its SCID).",
  preRotation:
    "The DID commits in advance to its next update key, so a stolen current key can't be used to take the DID over.",
  ttl: "How long, in seconds, resolvers may cache the DID before fetching it again.",
  alsoKnownAs:
    "Other identifiers the DID document claims for the same subject — for example agent names (example.com/@alice) or a did:scid alias.",
  stepUp:
    "A step-up passkey never signs anyone in; it only confirms sensitive actions (deleting a DID, purging a domain) for an account that already has one.",
  scopeDefault:
    "The owner may create DIDs on the listed domains; the default is the one used when they create a DID without choosing a domain.",
} as const;

export type GlossaryKey = keyof typeof GLOSSARY;

/**
 * A term with a small "?" that shows what it means. A disclosure button
 * rather than a hover tooltip, so it works by keyboard and touch too.
 */
export function Term({
  term,
  label,
  style,
}: {
  term: GlossaryKey;
  /** The visible word(s). */
  label: string;
  style?: StyleProp<TextStyle>;
}) {
  const [open, setOpen] = useState(false);
  const [focused, setFocused] = useState(false);
  const id = useId();
  return (
    <View style={styles.wrap}>
      <View style={styles.row}>
        <Text style={style}>{label}</Text>
        <Pressable
          role="button"
          aria-label={`What is “${label}”?`}
          aria-expanded={open}
          {...webAria(open ? { describedBy: id } : {})}
          onPress={() => setOpen((o) => !o)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          style={StyleSheet.flatten([styles.q, focused && focusRing])}
        >
          <Text style={styles.qText}>?</Text>
        </Pressable>
      </View>
      {open && (
        <Text nativeID={id} style={styles.definition}>
          {GLOSSARY[term]}
        </Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: {
    flexShrink: 1,
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
  },
  q: {
    width: 16,
    height: 16,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: colors.textTertiary,
    alignItems: "center",
    justifyContent: "center",
  },
  qText: {
    fontFamily: fonts.semibold,
    fontSize: 10,
    lineHeight: 12,
    color: colors.textTertiary,
  },
  definition: {
    marginTop: 4,
    maxWidth: 360,
    fontFamily: fonts.regular,
    fontSize: 12,
    lineHeight: 17,
    color: colors.textSecondary,
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.sm,
    padding: spacing.sm,
  },
});
