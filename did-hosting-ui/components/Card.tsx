import type { ReactNode } from "react";
import { StyleSheet, View, type StyleProp, type ViewStyle } from "react-native";

import { card } from "../lib/theme";
import { Heading } from "./Heading";

export interface CardProps {
  /** Rendered as a level-2 heading, and names the card's region. */
  title?: string;
  /** Beside the title (a count, an action). */
  headerRight?: ReactNode;
  children?: ReactNode;
  style?: StyleProp<ViewStyle>;
  testID?: string;
}

/** The console's panel: `theme.card`, with an optional heading. */
export function Card({ title, headerRight, children, style, testID }: CardProps) {
  return (
    <View
      style={[styles.card, style]}
      testID={testID}
      {...(title ? { role: "region" as const, "aria-label": title } : {})}
    >
      {(title || headerRight) && (
        <View style={styles.header}>
          {title ? (
            <Heading level={2} style={styles.title}>
              {title}
            </Heading>
          ) : (
            <View />
          )}
          {headerRight}
        </View>
      )}
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  card,
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    flexWrap: "wrap",
    gap: 8,
    marginBottom: 12,
  },
  title: {
    marginBottom: 0,
  },
});
