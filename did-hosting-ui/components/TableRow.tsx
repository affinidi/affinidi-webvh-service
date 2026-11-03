import { useState, type ComponentProps } from "react";
import { Pressable, StyleSheet, type StyleProp, type ViewStyle } from "react-native";

type Props = Omit<ComponentProps<typeof Pressable>, "style"> & {
  style?: StyleProp<ViewStyle>;
  hoverStyle?: StyleProp<ViewStyle>;
};

/**
 * A pressable table row that can sit under `<Link asChild>`.
 *
 * On web, Link's Slot merges its own props into its child by object spread,
 * so the child's `style` must be a plain object. A function `style`
 * (Pressable's `({ hovered }) => …`) spreads to nothing, which dropped a row's
 * `flexDirection: "row"` and stacked every cell; an array spreads to
 * `{0: …, 1: …}`, which React DOM refuses and the page goes blank. So the
 * caller passes `StyleSheet.flatten(...)`, and hover is tracked here instead.
 */
export function TableRow({ style, hoverStyle, children, ...rest }: Props) {
  const [hovered, setHovered] = useState(false);
  return (
    <Pressable
      {...rest}
      onHoverIn={() => setHovered(true)}
      onHoverOut={() => setHovered(false)}
      style={StyleSheet.flatten([style, hovered && hoverStyle])}
    >
      {children}
    </Pressable>
  );
}
