/**
 * Agent name chips — the human-memorable handles that redirect to a DID.
 *
 * An agent name is `webvh.storm.ws/@alice`: a name on a hosting domain where
 * `GET /@alice` redirects to the DID. This is the *display* surface — read
 * only, copyable, and repeated on both the DID list and the DID detail header.
 * Binding, parking and removing names live in the Agent Names card on the
 * detail page; those are deliberately not duplicated here, because a name you
 * want to hand someone shouldn't require scrolling past the document viewer,
 * and a management control repeated in a list row invites a mis-click.
 *
 * ## Placement
 *
 * Callers put these *under* the DID, never above it. An agent name is an
 * alias, not an identifier: promote it over the DID and a reader loses track
 * of which line is authoritative — doubly so on the list, where the card
 * heading is already a friendly label.
 *
 * ## Parked names are not shown
 *
 * The registry carries parked entries (`enabled: false`) so the management
 * card can list reservations. A parked name does not resolve, so rendering it
 * as a copyable handle would advertise a redirect that 404s. Callers holding
 * raw registry entries pass them through [`servedNames`] first.
 *
 * ## What gets copied
 *
 * Exactly what is shown — `webvh.storm.ws/@alice`, the form the agent-name FAQ
 * writes names in and the one a resolver accepts. A copy button that yields a
 * different string than the one on screen makes people paste twice to check.
 *
 * ## The community name
 *
 * An **empty** local part is the community name — `webvh.storm.ws/@`, the name
 * of the trust community that owns the domain. It needs no special handling
 * here: the chip is built by joining the host and the local part, so an empty
 * one renders and copies as `webvh.storm.ws/@` on its own. Do not filter empty
 * strings out of `names` on the assumption they are placeholders.
 */
import { useEffect, useRef, type ComponentRef, type ReactNode } from "react";
import { StyleSheet, Text, View } from "react-native";

import type { AgentNameEntry } from "../lib/api";
import { extractDidHost } from "../lib/domain";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { CopyButton } from "./CopyButton";

/**
 * The hosting domain a name is scoped to.
 *
 * Prefers the record's tagged `domain`, falling back to the DID identifier's
 * host — the same order `matchesDomain` uses, and for the same reason: legacy
 * slots M-01 hasn't backfilled still carry an empty `domain` while their DID
 * string has always held the authority.
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

/**
 * The names that actually resolve, in registry order.
 *
 * For callers whose only source is the registry — the DID list, which has no
 * document to read. The detail page derives its served set from the live
 * document's `alsoKnownAs` instead, which is what the edge actually serves,
 * and passes that; the two would only disagree mid-publish, and the page
 * should not contradict the Agent Names card sitting below it.
 */
export function servedNames(entries?: AgentNameEntry[]): string[] {
  return (entries ?? []).filter((e) => e.enabled).map((e) => e.name);
}

/**
 * Keep a click inside from following an enclosing link.
 *
 * Chips sit inside a pressable row on the DID list; without this a copy would
 * also navigate into the DID. The copy button's own press handler stops the
 * event reaching the row's React handler, but not the anchor's native default
 * action — so a native listener here, below the anchor, cancels that. A no-op
 * off the web.
 */
function NoNavigate({ children }: { children: ReactNode }) {
  const ref = useRef<ComponentRef<typeof View>>(null);
  useEffect(() => {
    const node = ref.current as unknown as Partial<HTMLElement> | null;
    if (!node || typeof node.addEventListener !== "function") return;
    const cancel = (e: Event) => e.preventDefault();
    node.addEventListener("click", cancel);
    return () => node.removeEventListener?.("click", cancel);
  }, []);
  return <View ref={ref}>{children}</View>;
}

export function AgentNameChips({
  names,
  domain,
  didId,
  size = "md",
  showHost = true,
}: {
  /** Names that resolve, local part only (`alice`). See [`servedNames`]. */
  names?: string[];
  domain?: string | null;
  didId?: string | null;
  /** `sm` for list rows, `md` for the detail header. */
  size?: "sm" | "md";
  /** `false` shows just `@name` (a table whose rows share the domain). The
   *  copied value is always the full `host/@name`. */
  showHost?: boolean;
}) {
  const host = agentNameHost(domain, didId);
  const served = names ?? [];
  // No served names is the common case. Render nothing rather than an empty
  // label, so those rows look exactly as they did before agent names existed.
  if (served.length === 0 || !host) return null;

  const small = size === "sm";

  return (
    <View style={styles.row}>
      {served.map((name) => {
        const full = formatAgentName(host, name);
        return (
          <View key={name} style={[styles.chip, small ? styles.chipSm : styles.chipMd]}>
            <Text style={[styles.chipText, small && styles.chipTextSm]} numberOfLines={1}>
              {/* The `@` carries the meaning; give it the accent so the eye
                  finds the handle without reading the domain first. */}
              {showHost && <Text style={styles.chipHost}>{host}/</Text>}
              <Text style={styles.chipAt}>@</Text>
              {name}
            </Text>
            <NoNavigate>
              <CopyButton
                value={full}
                accessibilityLabel={`Copy agent name ${full}`}
                style={styles.copyButton}
              />
            </NoNavigate>
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
    paddingVertical: 1,
    paddingHorizontal: spacing.sm,
  },
});
