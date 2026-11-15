/** Text styles the DID detail cards share. */

import { StyleSheet } from "react-native";

import { colors, fonts, spacing } from "../../lib/theme";

export const didStyles = StyleSheet.create({
  card: {
    marginBottom: spacing.lg,
  },
  hint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginBottom: spacing.md,
    lineHeight: 18,
  },
  warning: {
    color: colors.warning,
  },
  label: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
  },
  /** Uppercase field caption (`Watchers`, `TTL`). */
  caption: {
    fontSize: 12,
    fontFamily: fonts.semibold,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 1,
    marginBottom: spacing.xs,
  },
  mono: {
    fontFamily: fonts.mono,
    color: colors.textPrimary,
  },
  textarea: {
    backgroundColor: colors.bgPrimary,
    padding: spacing.md,
    fontSize: 13,
    fontFamily: fonts.mono,
    minHeight: 100,
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
  },
  spread: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: spacing.md,
  },
  stack: {
    marginTop: spacing.md,
    gap: spacing.sm,
  },
  error: {
    fontFamily: fonts.medium,
    color: colors.error,
    fontSize: 14,
  },
});
