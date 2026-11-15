import { useState } from "react";
import { Pressable, StyleSheet, Text, View, type StyleProp, type ViewStyle } from "react-native";

import { colors, focusRing, fonts, radii, spacing } from "../lib/theme";

export interface SegmentOption<T extends string> {
  value: T;
  label: string;
  /** A longer accessible name than the visible label. */
  accessibilityLabel?: string;
  disabled?: boolean;
}

export interface SegmentedControlProps<T extends string> {
  /** Names the group for assistive technology ("Role", "Time range"). */
  label: string;
  options: readonly SegmentOption<T>[];
  value: T | null;
  onChange: (value: T) => void;
  disabled?: boolean;
  /** Pressing the selected option again clears it (`onChange(null)`), for a
   *  picker whose "nothing chosen" state is meaningful. */
  onClear?: () => void;
  style?: StyleProp<ViewStyle>;
  testID?: string;
}

/**
 * A single-choice picker: a `radiogroup` of `radio` options, each announcing
 * whether it is `checked`, focusable, and chosen with Enter or Space.
 *
 * Replaces the per-screen rows of toggle `Pressable`s that drew the
 * selection in colour only and said nothing to a screen reader.
 */
export function SegmentedControl<T extends string>({
  label,
  options,
  value,
  onChange,
  disabled = false,
  onClear,
  style,
  testID,
}: SegmentedControlProps<T>) {
  return (
    <View role="radiogroup" aria-label={label} style={[styles.group, style]} testID={testID}>
      {options.map((opt) => (
        <Segment
          key={opt.value}
          option={opt}
          selected={opt.value === value}
          disabled={disabled || !!opt.disabled}
          onPress={() => {
            if (opt.value === value) {
              onClear?.();
            } else {
              onChange(opt.value);
            }
          }}
        />
      ))}
    </View>
  );
}

function Segment<T extends string>({
  option,
  selected,
  disabled,
  onPress,
}: {
  option: SegmentOption<T>;
  selected: boolean;
  disabled: boolean;
  onPress: () => void;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <Pressable
      role="radio"
      aria-checked={selected}
      aria-disabled={disabled}
      aria-label={option.accessibilityLabel ?? option.label}
      disabled={disabled}
      onPress={onPress}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      style={StyleSheet.flatten([
        styles.segment,
        selected && styles.selected,
        disabled && styles.disabled,
        focused && focusRing,
      ])}
    >
      <Text style={[styles.text, selected && styles.textSelected]}>
        {/* The selection is also drawn as a mark, not by colour alone. */}
        {selected ? "✓ " : ""}
        {option.label}
      </Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  group: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.sm,
  },
  segment: {
    paddingVertical: spacing.xs + 2,
    paddingHorizontal: spacing.md,
    borderRadius: radii.sm,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.bgTertiary,
  },
  selected: {
    borderColor: colors.accent,
    backgroundColor: "rgba(59, 113, 255, 0.18)",
  },
  disabled: {
    opacity: 0.5,
  },
  text: {
    fontFamily: fonts.medium,
    fontSize: 13,
    color: colors.textSecondary,
  },
  textSelected: {
    color: colors.textPrimary,
  },
});
