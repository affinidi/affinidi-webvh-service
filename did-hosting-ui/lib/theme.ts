/** Affinidi brand design tokens */

import type { TextStyle, ViewStyle } from "react-native";

export const colors = {
  // Primary palette
  bgPrimary: "#040823", // Black Pearl — main background
  bgSecondary: "#0C1033", // Slightly lighter panel/card background
  bgTertiary: "#141840", // Elevated cards, inputs
  bgHeader: "#060B28", // Header/nav background

  // Accent
  accent: "#3B71FF", // Affinidi blue — primary buttons, links
  accentHover: "#5588FF",
  // Filled button background. White on `accent` is 4.2:1, under AA; this
  // darker blue is 5.2:1. `accent` stays for borders, focus and icons.
  accentButton: "#2F62E8",
  accentButtonHover: "#2A5BDB",
  teal: "#1FE5CD", // Secondary accent — success, highlights
  tealMuted: "rgba(31, 229, 205, 0.15)", // Badge background

  // Text
  textPrimary: "#FFFFFF",
  textSecondary: "#A0A8C8", // Muted body text
  // Labels, timestamps, placeholders. #8F96B8 clears WCAG AA (4.5:1) on every
  // background below; the old #6B7194 was 3.6–4.2:1.
  textTertiary: "#8F96B8",
  textOnAccent: "#FFFFFF",

  // Status
  success: "#1FE5CD",
  error: "#FF5C5C",
  errorBg: "rgba(255, 92, 92, 0.12)",
  warning: "#FFB547",

  // Borders
  border: "#1C2148",
  borderFocus: "#3B71FF",
  // Keyboard focus outline — bright enough to see on every background.
  focusRing: "#8FB0FF",

  // Misc
  overlay: "rgba(4, 8, 35, 0.8)",
} as const;

export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 24,
  xxl: 32,
  xxxl: 48,
} as const;

export const radii = {
  sm: 6,
  md: 10,
  lg: 14,
  full: 9999,
} as const;

export const fonts = {
  regular: "Figtree_400Regular",
  medium: "Figtree_500Medium",
  semibold: "Figtree_600SemiBold",
  bold: "Figtree_700Bold",
  mono: "monospace",
} as const;

// ---------------------------------------------------------------------------
// Shared component styles
// ---------------------------------------------------------------------------

/** Standard card container. */
export const card: ViewStyle = {
  backgroundColor: colors.bgSecondary,
  borderRadius: radii.lg,
  borderWidth: 1,
  borderColor: colors.border,
  padding: spacing.xl,
};

/** Primary action button. */
export const primaryButton: ViewStyle = {
  backgroundColor: colors.accentButton,
  borderRadius: radii.sm,
  paddingVertical: 14,
  paddingHorizontal: spacing.xl,
  alignItems: "center",
};

/** Destructive / danger action button (outline style). */
export const dangerButton: ViewStyle = {
  backgroundColor: "transparent",
  borderRadius: radii.sm,
  borderWidth: 1,
  borderColor: colors.error,
  paddingVertical: 14,
  paddingHorizontal: spacing.xl,
  alignItems: "center",
};

/** The keyboard focus outline every interactive primitive draws (web). */
export const focusRing: ViewStyle = {
  outlineColor: colors.focusRing,
  outlineStyle: "solid",
  outlineWidth: 2,
  outlineOffset: 2,
};

/** Muted hint text below inputs or sections. */
export const hintText: TextStyle = {
  fontFamily: fonts.regular,
  fontSize: 13,
  color: colors.textSecondary,
};
