import { useState, type ComponentRef, type ReactNode, type Ref } from "react";
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  type GestureResponderEvent,
  type StyleProp,
  type TextStyle,
  type ViewStyle,
} from "react-native";

import { webAria } from "../lib/a11y";
import { colors, focusRing, fonts, radii, spacing } from "../lib/theme";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";
export type ButtonSize = "md" | "sm";

/** What `buttonRef` points at: the pressable element (a DOM node on web). */
export type ButtonHandle = ComponentRef<typeof Pressable>;

export interface ButtonProps {
  /** The visible text. Also the accessible name unless `accessibilityLabel`
   *  says otherwise. */
  label?: string;
  /** Custom content in place of `label` — then `accessibilityLabel` is
   *  required, because the name cannot be read off arbitrary children. */
  children?: ReactNode;
  onPress?: (e: GestureResponderEvent) => void;
  variant?: ButtonVariant;
  size?: ButtonSize;
  disabled?: boolean;
  /** Working: shows a spinner, announces `aria-busy`, ignores presses. */
  busy?: boolean;
  /** Text shown while `busy` (default: `label`). */
  busyLabel?: string;
  /** The accessible name, when the visible text is not enough
   *  ("Copy" → "Copy DID did:webvh:…"). */
  accessibilityLabel?: string;
  /** A toggle button's state: rendered as `aria-pressed`. */
  pressed?: boolean;
  /** A disclosure button's state: rendered as `aria-expanded`. */
  expanded?: boolean;
  style?: StyleProp<ViewStyle>;
  textStyle?: StyleProp<TextStyle>;
  testID?: string;
  /** The underlying element, to move focus to it (a dialog focuses Cancel). */
  buttonRef?: Ref<ButtonHandle>;
}

/**
 * The console's one button.
 *
 * `role="button"` with its name and `disabled` / `busy` state, a visible focus
 * ring for keyboard users, and Enter and Space activation — `react-native-web`'s
 * press responder fires `onPress` on both keys for a button role. Styles are
 * flattened to one object so it can also sit under `<Link asChild>` (see
 * `TableRow.tsx` for why a function or array style breaks there).
 */
export function Button({
  label,
  children,
  onPress,
  variant = "primary",
  size = "md",
  disabled = false,
  busy = false,
  busyLabel,
  accessibilityLabel,
  pressed,
  expanded,
  style,
  textStyle,
  testID,
  buttonRef,
}: ButtonProps) {
  const [focused, setFocused] = useState(false);
  const [hovered, setHovered] = useState(false);
  const inert = disabled || busy;
  const v = VARIANTS[variant];

  return (
    <Pressable
      ref={buttonRef}
      role="button"
      aria-label={accessibilityLabel ?? label}
      aria-disabled={inert}
      aria-busy={busy}
      aria-expanded={expanded}
      {...webAria(pressed === undefined ? {} : { pressed })}
      disabled={inert}
      onPress={onPress}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      onHoverIn={() => setHovered(true)}
      onHoverOut={() => setHovered(false)}
      testID={testID}
      style={StyleSheet.flatten([
        styles.base,
        size === "sm" ? styles.sm : styles.md,
        v.container,
        hovered && !inert && v.hover,
        pressed && v.hover,
        inert && styles.disabled,
        focused && styles.focused,
        style,
      ])}
    >
      {busy && (
        <ActivityIndicator
          size="small"
          color={v.text.color as string}
          style={styles.spinner}
          aria-hidden
        />
      )}
      {children ?? (
        <Text style={[styles.text, size === "sm" && styles.textSm, v.text, textStyle]}>
          {busy && busyLabel ? busyLabel : label}
        </Text>
      )}
    </Pressable>
  );
}

const VARIANTS: Record<ButtonVariant, { container: ViewStyle; hover: ViewStyle; text: TextStyle }> =
  {
    primary: {
      container: { backgroundColor: colors.accentButton },
      hover: { backgroundColor: colors.accentButtonHover },
      text: { color: colors.textOnAccent },
    },
    secondary: {
      container: {
        backgroundColor: colors.bgTertiary,
        borderWidth: 1,
        borderColor: colors.border,
      },
      hover: { borderColor: colors.accent },
      text: { color: colors.textPrimary },
    },
    danger: {
      container: {
        backgroundColor: "transparent",
        borderWidth: 1,
        borderColor: colors.error,
      },
      hover: { backgroundColor: colors.errorBg },
      text: { color: colors.error },
    },
    ghost: {
      container: { backgroundColor: "transparent" },
      hover: { backgroundColor: colors.bgTertiary },
      text: { color: colors.accentHover },
    },
  };

const styles = StyleSheet.create({
  base: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radii.sm,
  },
  md: {
    paddingVertical: spacing.md,
    paddingHorizontal: spacing.xl,
  },
  sm: {
    paddingVertical: spacing.xs + 2,
    paddingHorizontal: spacing.md,
  },
  text: {
    fontFamily: fonts.semibold,
    fontSize: 15,
  },
  textSm: {
    fontSize: 13,
  },
  disabled: {
    opacity: 0.5,
  },
  focused: focusRing,
  spinner: {
    marginRight: spacing.sm,
  },
});
