import { useState, type ComponentProps } from "react";
import { Pressable, StyleSheet, type StyleProp, type ViewStyle } from "react-native";

type Props = Omit<ComponentProps<typeof Pressable>, "style"> & {
  style?: StyleProp<ViewStyle>;
  hoverStyle?: StyleProp<ViewStyle>;
};

/**
 * A pressable table row that can sit under `<Link asChild>`.
 *
 * On web, Link merges its own props into its child and does not resolve a
 * function `style` (Pressable's `({ hovered }) => …`). That dropped a row's
 * `flexDirection: "row"` and stacked every cell. So the style handed over is a
 * flattened object, and hover is tracked here instead.
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
