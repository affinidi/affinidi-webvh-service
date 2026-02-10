/** Affinidi brand design tokens */

export const colors = {
  // Primary palette
  bgPrimary: "#040823", // Black Pearl — main background
  bgSecondary: "#0C1033", // Slightly lighter panel/card background
  bgTertiary: "#141840", // Elevated cards, inputs
  bgHeader: "#060B28", // Header/nav background

  // Accent
  accent: "#3B71FF", // Affinidi blue — primary buttons, links
  accentHover: "#5588FF",
  teal: "#1FE5CD", // Secondary accent — success, highlights
  tealMuted: "rgba(31, 229, 205, 0.15)", // Badge background

  // Text
  textPrimary: "#FFFFFF",
  textSecondary: "#A0A8C8", // Muted body text
  textTertiary: "#6B7194", // Labels, timestamps
  textOnAccent: "#FFFFFF",

  // Status
  success: "#1FE5CD",
  error: "#FF5C5C",
  errorBg: "rgba(255, 92, 92, 0.12)",
  warning: "#FFB547",

  // Borders
  border: "#1C2148",
  borderFocus: "#3B71FF",

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
