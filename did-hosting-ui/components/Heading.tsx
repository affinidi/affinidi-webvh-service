import type { ReactNode } from "react";
import { StyleSheet, Text, type StyleProp, type TextStyle } from "react-native";

import { webAria } from "../lib/a11y";
import { colors, fonts, spacing } from "../lib/theme";

export interface HeadingProps {
  /** 1 for a page title, 2 for a card or section, 3 below that. */
  level?: 1 | 2 | 3;
  children: ReactNode;
  style?: StyleProp<TextStyle>;
  nativeID?: string;
}

/**
 * A heading a screen reader can navigate by: `role="heading"` with
 * `aria-level`, so react-native-web renders a real heading rather than a
 * styled `div`.
 */
export function Heading({ level = 1, children, style, nativeID }: HeadingProps) {
  return (
    <Text
      role="heading"
      {...webAria({ level })}
      nativeID={nativeID}
      style={[level === 1 ? styles.h1 : level === 2 ? styles.h2 : styles.h3, style]}
    >
      {children}
    </Text>
  );
}

const styles = StyleSheet.create({
  h1: {
    fontSize: 24,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    marginBottom: spacing.lg,
  },
  h2: {
    fontSize: 18,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  h3: {
    fontSize: 15,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.sm,
  },
});
