import { StyleSheet, Text, View } from "react-native";

import type { AclEntry } from "../../lib/api";
import type { ScopeDraft, ScopeKind } from "../../lib/acl-scope";
import { colors, fonts, spacing } from "../../lib/theme";
import { Button } from "../Button";
import { SegmentedControl } from "../SegmentedControl";
import { Term } from "../Term";

/** A domain as the scope editor offers it. */
export interface AvailableDomain {
  name: string;
  disabled: boolean;
}

const KINDS = [
  { value: "all", label: "All" },
  { value: "allowed", label: "Specific" },
  { value: "allowed_with_default", label: "Specific + default" },
] as const;

/** Renders the current scope of an ACL entry as a compact read-only
 * cluster of chips. "All domains" collapses to a single chip; otherwise
 * each allowed domain renders as a chip, with the default marked by a
 * leading star. Used in the row read view (not the editor). */
export function ScopeBadges({ entry }: { entry: AclEntry }) {
  const scope = entry.domains;
  if (!scope || scope.kind === "all") {
    return (
      <View style={styles.chip}>
        <Text style={styles.chipText}>All domains</Text>
      </View>
    );
  }
  const def = scope.kind === "allowed_with_default" ? scope.default : null;
  return (
    <View style={styles.chipRow}>
      {scope.domains.map((d) => {
        const isDefault = d === def;
        return (
          <View key={d} style={[styles.chip, isDefault && styles.chipDefault]}>
            <Text style={[styles.chipText, isDefault && styles.chipTextDefault]} numberOfLines={1}>
              {isDefault ? `★ ${d} (default)` : d}
            </Text>
          </View>
        );
      })}
    </View>
  );
}

/** Inline editor for a `DomainScope` draft. Three modes:
 * - All domains: no further input
 * - Specific domains: multi-select toggle buttons
 * - Specific + default: multi-select + a single-choice default
 *
 * `availableDomains` is sourced from `useDomains()` so the list always
 * reflects the live catalog (Access Control is admin-only, so this is the
 * full set).
 */
export function ScopeEditor({
  draft,
  availableDomains,
  onChange,
}: {
  draft: ScopeDraft;
  availableDomains: AvailableDomain[];
  onChange: (next: ScopeDraft) => void;
}) {
  const toggleDomain = (name: string) => {
    const has = draft.domains.includes(name);
    const next = has ? draft.domains.filter((d) => d !== name) : [...draft.domains, name];
    let nextDefault = draft.default;
    if (draft.kind === "allowed_with_default" && !next.includes(nextDefault)) {
      nextDefault = next[0] ?? "";
    }
    onChange({ ...draft, domains: next, default: nextDefault });
  };

  const setKind = (kind: ScopeKind) => {
    if (kind === "all") {
      onChange({ kind, domains: [], default: "" });
      return;
    }
    if (kind === "allowed") {
      onChange({ ...draft, kind, default: "" });
      return;
    }
    // allowed_with_default — auto-pick the first selected as default if
    // the user hasn't chosen one yet.
    const def =
      draft.default && draft.domains.includes(draft.default)
        ? draft.default
        : (draft.domains[0] ?? "");
    onChange({ ...draft, kind, default: def });
  };

  return (
    <View style={styles.editor}>
      <Term term="scopeDefault" label="Domain scope" style={styles.label} />
      <SegmentedControl
        label="Domain scope"
        options={KINDS}
        value={draft.kind}
        onChange={setKind}
        style={styles.kindRow}
      />

      {draft.kind !== "all" && (
        <View>
          <Text style={styles.hint}>
            {draft.kind === "allowed"
              ? "Owner can create DIDs on any of the selected domains."
              : "Owner can create on any selected domain; new DIDs default to the starred one."}
          </Text>
          {availableDomains.length === 0 ? (
            <Text style={styles.empty}>
              No domains configured yet — create one on the Domains page.
            </Text>
          ) : (
            <View style={styles.wrap} role="group" aria-label="Allowed domains">
              {availableDomains.map((d) => {
                const selected = draft.domains.includes(d.name);
                const isDefault = draft.kind === "allowed_with_default" && draft.default === d.name;
                const text = `${isDefault ? "★ " : ""}${d.name}${d.disabled ? "  (disabled)" : ""}`;
                return (
                  <Button
                    key={d.name}
                    label={selected ? `✓ ${text}` : text}
                    accessibilityLabel={`${d.name}${d.disabled ? " (disabled)" : ""}`}
                    pressed={selected}
                    variant="secondary"
                    size="sm"
                    onPress={() => toggleDomain(d.name)}
                    style={[
                      isDefault && styles.domainDefault,
                      d.disabled ? styles.domainDisabled : undefined,
                    ]}
                  />
                );
              })}
            </View>
          )}
          {draft.kind === "allowed_with_default" && draft.domains.length > 1 && (
            <View>
              <Text style={styles.label}>Default domain</Text>
              <SegmentedControl
                label="Default domain"
                options={draft.domains.map((name) => ({ value: name, label: name }))}
                value={draft.default || null}
                onChange={(name) => onChange({ ...draft, default: name })}
                style={styles.wrap}
              />
            </View>
          )}
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  editor: {
    marginTop: spacing.sm,
    marginBottom: spacing.sm,
  },
  label: {
    fontSize: 11,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
    marginBottom: 4,
  },
  kindRow: {
    marginBottom: spacing.sm,
  },
  hint: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginBottom: spacing.sm,
  },
  empty: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
    fontStyle: "italic",
    marginBottom: spacing.sm,
  },
  wrap: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.xs,
    marginBottom: spacing.sm,
  },
  domainDefault: {
    borderColor: colors.teal,
  },
  domainDisabled: {
    opacity: 0.5,
  },
  chipRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.xs,
    flex: 1,
  },
  chip: {
    backgroundColor: colors.bgTertiary,
    borderRadius: 999,
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
  },
  chipDefault: {
    backgroundColor: "rgba(31, 229, 205, 0.18)",
  },
  chipText: {
    fontSize: 11,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
  },
  chipTextDefault: {
    color: colors.teal,
  },
});
