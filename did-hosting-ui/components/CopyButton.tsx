import * as Clipboard from "expo-clipboard";
import { useEffect, useRef, useState } from "react";
import { StyleSheet, Text, View, type StyleProp, type ViewStyle } from "react-native";

import { colors, fonts, spacing } from "../lib/theme";
import { Button, type ButtonSize, type ButtonVariant } from "./Button";

/** Shown when the clipboard refuses the write. */
export const COPY_FAILED = "Copy failed — select and copy manually";

/** How long "Copied" stays on the button. */
const CONFIRM_MS = 2000;

export interface CopyButtonProps {
  /** What goes on the clipboard. */
  value: string;
  /** The button text (default "Copy"). */
  label?: string;
  /** The text after a successful copy (default "Copied"). */
  copiedLabel?: string;
  /** The accessible name — say *what* is copied ("Copy invite link"). */
  accessibilityLabel?: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  style?: StyleProp<ViewStyle>;
  /** Called after a successful copy. */
  onCopied?: () => void;
}

/**
 * Copy `value` to the clipboard, and say whether it worked.
 *
 * `Clipboard.setStringAsync` rejects on a plain-HTTP (non-localhost)
 * deployment and when the browser denies the permission. Awaited bare, that
 * failure was silent — and for a one-time invite link or claim code the
 * operator could believe it was copied. Here a failure says so, and the value
 * is shown as selectable text beside the button so it can still be copied by
 * hand.
 */
export function CopyButton({
  value,
  label = "Copy",
  copiedLabel = "Copied",
  accessibilityLabel,
  variant = "secondary",
  size = "sm",
  style,
  onCopied,
}: CopyButtonProps) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  // A new value is a new copy: forget the last attempt's outcome.
  useEffect(() => {
    setState("idle");
  }, [value]);

  const copy = async () => {
    if (timer.current) clearTimeout(timer.current);
    try {
      await Clipboard.setStringAsync(value);
      setState("copied");
      onCopied?.();
      timer.current = setTimeout(() => setState("idle"), CONFIRM_MS);
    } catch {
      // Stays until the next attempt: the fallback text is how the operator
      // gets the value now.
      setState("failed");
    }
  };

  return (
    <View style={styles.wrap}>
      <Button
        label={state === "copied" ? copiedLabel : label}
        accessibilityLabel={accessibilityLabel ?? label}
        variant={variant}
        size={size}
        onPress={copy}
        style={style}
      />
      <Text aria-live="polite" style={styles.status}>
        {state === "copied" ? copiedLabel : ""}
      </Text>
      {state === "failed" && (
        <View style={styles.failed}>
          <Text role="alert" style={styles.failedText}>
            {COPY_FAILED}
          </Text>
          <Text selectable style={styles.value}>
            {value}
          </Text>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: {
    alignItems: "flex-start",
  },
  // Announced to screen readers, not drawn: the button text already shows it.
  status: {
    position: "absolute",
    width: 1,
    height: 1,
    overflow: "hidden",
    opacity: 0,
  },
  failed: {
    marginTop: spacing.xs,
    maxWidth: 480,
  },
  failedText: {
    fontFamily: fonts.medium,
    fontSize: 12,
    color: colors.warning,
  },
  value: {
    marginTop: spacing.xs,
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.textPrimary,
  },
});
