/**
 * Domain switcher — dropdown chip in the NavBar that picks the
 * active domain for downstream views.
 *
 * Design choice: a single pressable chip that opens a popover with
 * the list, rather than Chrome-tab-style horizontal tabs. Rationale:
 * - tabs assume small N (3-5); admins often have 10+ domains.
 * - chip + popover scales to many domains and stays compact on
 *   narrow viewports.
 * - the chip itself surfaces enough info at a glance (current
 *   selection + open affordance).
 *
 * Admin-only: when the caller's scope is `All` AND they have admin
 * role, the popover includes an "All domains" pseudo-option that
 * unsets the filter. Non-admins always have a concrete domain
 * selected.
 */

import { memo, useState } from "react";
import { Pressable, StyleSheet, Text, View, ScrollView } from "react-native";
import { Dialog } from "./Dialog";
import { useDomains } from "./DomainProvider";
import { useAuth } from "./AuthProvider";
import { colors, fonts, radii, spacing } from "../lib/theme";

export const DomainSwitcher = memo(function DomainSwitcher() {
  const { domains, currentDomain, setCurrentDomain, loaded } = useDomains();
  const { role } = useAuth();
  const [open, setOpen] = useState(false);

  if (!loaded || domains.length === 0) {
    return null;
  }

  const label = currentDomain === null ? "All domains" : currentDomain;

  const showAllOption = role === "admin";

  const pickAndClose = (next: string | null) => {
    setCurrentDomain(next);
    setOpen(false);
  };

  return (
    <View>
      <Pressable
        role="button"
        aria-label={`Current domain: ${label}. Tap to switch.`}
        aria-expanded={open}
        onPress={() => setOpen(true)}
        style={({ pressed }) => [styles.chip, pressed && styles.chipPressed]}
      >
        <View style={styles.chipDot} />
        <Text style={styles.chipText} numberOfLines={1}>
          {label}
        </Text>
        <Text style={styles.chipCaret}>▾</Text>
      </Pressable>

      <Dialog
        visible={open}
        title="Switch domain"
        onClose={() => setOpen(false)}
        style={styles.popover}
      >
        <ScrollView style={styles.list} role="radiogroup" aria-label="Domain">
          {showAllOption && (
            <DomainOption
              label="All domains"
              hint="Show DIDs from every configured domain"
              active={currentDomain === null}
              onPress={() => pickAndClose(null)}
            />
          )}
          {domains.map((d) => (
            <DomainOption
              key={d.name}
              label={d.name}
              hint={[
                d.defaultDomain ? "Default" : null,
                d.status === "disabled" ? "Disabled" : null,
                d.label ?? null,
              ]
                .filter(Boolean)
                .join(" · ")}
              active={currentDomain === d.name}
              disabled={d.status === "disabled"}
              onPress={() => pickAndClose(d.name)}
            />
          ))}
        </ScrollView>
      </Dialog>
    </View>
  );
});

const DomainOption = memo(function DomainOption({
  label,
  hint,
  active,
  disabled,
  onPress,
}: {
  label: string;
  hint?: string;
  active: boolean;
  disabled?: boolean;
  onPress: () => void;
}) {
  return (
    <Pressable
      role="radio"
      aria-checked={active}
      aria-disabled={!!disabled}
      aria-label={hint ? `${label}, ${hint}` : label}
      onPress={onPress}
      disabled={disabled}
      style={({ pressed }) => [
        styles.option,
        active && styles.optionActive,
        pressed && !disabled && styles.optionPressed,
        disabled && styles.optionDisabled,
      ]}
    >
      <View style={styles.optionRow}>
        <Text
          style={[
            styles.optionLabel,
            active && styles.optionLabelActive,
            disabled && styles.optionLabelDisabled,
          ]}
          numberOfLines={1}
        >
          {label}
        </Text>
        {active && <Text style={styles.optionTick}>✓</Text>}
      </View>
      {!!hint && <Text style={styles.optionHint}>{hint}</Text>}
    </Pressable>
  );
});

const styles = StyleSheet.create({
  chip: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.full,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
    maxWidth: 280,
  },
  chipPressed: {
    backgroundColor: colors.bgSecondary,
    borderColor: colors.borderFocus,
  },
  chipDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: colors.teal,
  },
  chipText: {
    fontFamily: fonts.medium,
    fontSize: 13,
    color: colors.textPrimary,
    flexShrink: 1,
  },
  chipCaret: {
    fontFamily: fonts.regular,
    fontSize: 11,
    color: colors.textTertiary,
  },
  popover: {
    width: "100%",
    maxWidth: 420,
    maxHeight: 440,
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.md,
    gap: spacing.sm,
  },
  list: {
    marginTop: spacing.xs,
  },
  option: {
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderRadius: radii.md,
    marginBottom: 2,
  },
  optionActive: {
    backgroundColor: colors.bgTertiary,
  },
  optionPressed: {
    backgroundColor: colors.bgHeader,
  },
  optionDisabled: {
    opacity: 0.5,
  },
  optionRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: spacing.md,
  },
  optionLabel: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 14,
    color: colors.textPrimary,
  },
  optionLabelActive: {
    color: colors.teal,
  },
  optionLabelDisabled: {
    textDecorationLine: "line-through",
  },
  optionTick: {
    fontFamily: fonts.semibold,
    color: colors.teal,
    fontSize: 14,
  },
  optionHint: {
    fontFamily: fonts.regular,
    fontSize: 11,
    color: colors.textTertiary,
    marginTop: 2,
  },
});
