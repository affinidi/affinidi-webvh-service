import { useState, type ReactNode } from "react";
import { Pressable, StyleSheet, type StyleProp, type ViewStyle } from "react-native";

interface Props {
  style?: StyleProp<ViewStyle>;
  hoverStyle?: StyleProp<ViewStyle>;
  children?: ReactNode;
}

/**
 * A table row (`role="row"`) that highlights under the pointer.
 *
 * The row itself is not interactive — it is not focusable and has no press
 * handler. What a row leads to is a link inside it (the DID list's name
 * cell), and its actions (copy, QR) sit beside that link. A row that was
 * itself a link wrapped those buttons, an interactive control inside
 * another, which screen readers and keyboards cannot use. `Pressable` is
 * used only for its hover events.
 */
export function TableRow({ style, hoverStyle, children }: Props) {
  const [hovered, setHovered] = useState(false);
  return (
    <Pressable
      role="row"
      focusable={false}
      tabIndex={-1}
      onHoverIn={() => setHovered(true)}
      onHoverOut={() => setHovered(false)}
      style={StyleSheet.flatten([style, hovered && hoverStyle])}
    >
      {children}
    </Pressable>
  );
}
