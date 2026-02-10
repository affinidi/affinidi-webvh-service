import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { colors, fonts } from "../lib/theme";

/**
 * Affinidi brand logomark + wordmark.
 *
 * The mark represents data flow (vertical bars) converging through
 * a crescent arc — the core Affinidi visual motif.
 */
export function AffinidiLogo({
  size = 32,
  showWordmark = true,
}: {
  size?: number;
  showWordmark?: boolean;
}) {
  // SVG rendered as a data-uri background image for cross-platform compat
  const svgContent = `
<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="40" height="40" rx="8" fill="#3B71FF"/>
  <g transform="translate(8,8)">
    <rect x="0" y="2" width="2.5" height="20" rx="1.25" fill="white" opacity="0.4"/>
    <rect x="5" y="0" width="2.5" height="24" rx="1.25" fill="white" opacity="0.6"/>
    <rect x="10" y="1" width="2.5" height="22" rx="1.25" fill="white" opacity="0.8"/>
    <rect x="15" y="3" width="2.5" height="18" rx="1.25" fill="white"/>
    <rect x="20" y="5" width="2.5" height="14" rx="1.25" fill="white" opacity="0.7"/>
    <path d="M 2 22 Q 12 30 24 16" stroke="#1FE5CD" stroke-width="2.5" stroke-linecap="round" fill="none"/>
  </g>
</svg>`.trim();

  const encoded = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgContent)}`;

  return (
    <View style={styles.container}>
      <View
        style={[
          styles.mark,
          {
            width: size,
            height: size,
            borderRadius: size * 0.2,
            overflow: "hidden",
          },
        ]}
      >
        {/* eslint-disable-next-line react-native/no-inline-styles */}
        <img
          src={encoded}
          width={size}
          height={size}
          alt="Affinidi"
          style={{ display: "block" } as any}
        />
      </View>
      {showWordmark && (
        <Text style={styles.wordmark}>
          Affinidi <Text style={styles.wordmarkLight}>WebVH</Text>
        </Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  mark: {
    backgroundColor: colors.accent,
  },
  wordmark: {
    fontSize: 18,
    fontFamily: fonts.bold,
    fontWeight: "700",
    color: colors.textPrimary,
    letterSpacing: 0.3,
  },
  wordmarkLight: {
    fontFamily: fonts.regular,
    fontWeight: "400",
    color: colors.textSecondary,
  },
});
