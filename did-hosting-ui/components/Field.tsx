import { useId, useState, type ComponentRef, type Ref } from "react";
import {
  StyleSheet,
  Text,
  TextInput,
  View,
  type StyleProp,
  type TextInputProps,
  type ViewStyle,
} from "react-native";

import { webAria } from "../lib/a11y";
import { colors, focusRing, fonts, radii, spacing } from "../lib/theme";

export interface FieldProps extends Omit<TextInputProps, "style"> {
  /** The visible label, and the input's accessible name. */
  label: string;
  /** Hide the label visually but keep it as the accessible name — for an
   *  input whose purpose the layout already shows (a search box). */
  hideLabel?: boolean;
  /** Help text under the input, announced with it. */
  hint?: string;
  /** An error under the input; marks it `aria-invalid`. */
  error?: string | null;
  required?: boolean;
  /** Called on Enter — the form's submit. Same as `onSubmitEditing`. */
  onSubmit?: () => void;
  style?: StyleProp<ViewStyle>;
  inputStyle?: TextInputProps["style"];
  inputRef?: Ref<ComponentRef<typeof TextInput>>;
}

/**
 * A labelled text input.
 *
 * The label is a real label (`aria-labelledby`), hint and error are its
 * description, an error sets `aria-invalid`, the focused input draws the focus
 * ring, and Enter calls `onSubmit` — so a one-field form submits from the
 * keyboard the way a browser form would.
 */
export function Field({
  label,
  hideLabel,
  hint,
  error,
  required,
  onSubmit,
  style,
  inputStyle,
  inputRef,
  onFocus,
  onBlur,
  ...input
}: FieldProps) {
  const id = useId();
  const labelId = `${id}-label`;
  const hintId = `${id}-hint`;
  const [focused, setFocused] = useState(false);
  // A caller-given name replaces the visible label as the accessible name
  // (aria-labelledby would otherwise win over aria-label).
  const ownName = input.accessibilityLabel ?? input["aria-label"];
  const described = [hint ? hintId : null, error ? `${id}-error` : null].filter(Boolean).join(" ");

  return (
    <View style={[styles.field, style]}>
      <Text nativeID={labelId} style={hideLabel ? styles.hidden : styles.label}>
        {label}
        {required ? " *" : ""}
      </Text>
      <TextInput
        ref={inputRef}
        {...(ownName
          ? { "aria-label": ownName }
          : { "aria-labelledby": labelId, "aria-label": label })}
        {...webAria({
          ...(described ? { describedBy: described } : {}),
          ...(error ? { invalid: true } : {}),
          ...(required ? { required: true } : {}),
        })}
        placeholderTextColor={colors.textTertiary}
        onSubmitEditing={onSubmit}
        onFocus={(e) => {
          setFocused(true);
          onFocus?.(e);
        }}
        onBlur={(e) => {
          setFocused(false);
          onBlur?.(e);
        }}
        {...input}
        style={[styles.input, error ? styles.inputError : null, focused && focusRing, inputStyle]}
      />
      {hint ? (
        <Text nativeID={hintId} style={styles.hint}>
          {hint}
        </Text>
      ) : null}
      {error ? (
        <Text nativeID={`${id}-error`} role="alert" style={styles.error}>
          {error}
        </Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  field: {
    marginBottom: spacing.md,
  },
  label: {
    fontFamily: fonts.medium,
    fontSize: 13,
    color: colors.textSecondary,
    marginBottom: spacing.xs,
  },
  // Visually hidden, still read.
  hidden: {
    position: "absolute",
    width: 1,
    height: 1,
    overflow: "hidden",
    opacity: 0,
  },
  input: {
    backgroundColor: colors.bgTertiary,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: radii.sm,
    paddingVertical: spacing.sm + 2,
    paddingHorizontal: spacing.md,
    color: colors.textPrimary,
    fontFamily: fonts.regular,
    fontSize: 14,
  },
  inputError: {
    borderColor: colors.error,
  },
  hint: {
    fontFamily: fonts.regular,
    fontSize: 12,
    color: colors.textTertiary,
    marginTop: spacing.xs,
  },
  error: {
    fontFamily: fonts.regular,
    fontSize: 12,
    color: colors.error,
    marginTop: spacing.xs,
  },
});
