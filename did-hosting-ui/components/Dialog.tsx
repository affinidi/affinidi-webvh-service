import { useId, type ReactNode } from "react";
import { Modal, Pressable, StyleSheet, View, type StyleProp, type ViewStyle } from "react-native";

import { colors, radii, spacing } from "../lib/theme";
import { Button } from "./Button";
import { Heading } from "./Heading";

export interface DialogProps {
  visible: boolean;
  /** The dialog's heading, and its accessible name. */
  title: string;
  /** Escape, the backdrop, and the close button call this. */
  onClose: () => void;
  children?: ReactNode;
  /** Buttons along the bottom (Cancel / Confirm). */
  actions?: ReactNode;
  /** Hide the × in the corner — for a dialog whose actions already close it. */
  hideCloseButton?: boolean;
  style?: StyleProp<ViewStyle>;
  testID?: string;
}

/**
 * A modal dialog.
 *
 * Built on React Native's `Modal`, which on web renders `role="dialog"` with
 * `aria-modal`, traps focus inside while open, returns it on close, and calls
 * `onRequestClose` on Escape. This adds the heading that names the dialog
 * (`aria-labelledby`), a backdrop that closes it, and a labelled close button.
 */
export function Dialog({
  visible,
  title,
  onClose,
  children,
  actions,
  hideCloseButton = false,
  style,
  testID,
}: DialogProps) {
  const titleId = `${useId()}-title`;
  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={onClose}
      aria-labelledby={titleId}
    >
      <View style={styles.backdrop}>
        <Pressable
          style={StyleSheet.absoluteFill}
          onPress={onClose}
          aria-label="Close dialog"
          // The backdrop is a mouse affordance; keyboard users have Escape
          // and the close button, so it stays out of the tab order.
          focusable={false}
          tabIndex={-1}
        />
        <View style={[styles.panel, style]} testID={testID}>
          <View style={styles.header}>
            <Heading level={2} nativeID={titleId} style={styles.title}>
              {title}
            </Heading>
            {!hideCloseButton && (
              <Button
                label="×"
                accessibilityLabel="Close"
                variant="ghost"
                size="sm"
                onPress={onClose}
              />
            )}
          </View>
          {children}
          {actions ? <View style={styles.actions}>{actions}</View> : null}
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.overlay,
    padding: spacing.xl,
  },
  panel: {
    width: "100%",
    maxWidth: 520,
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: spacing.md,
  },
  title: {
    marginBottom: 0,
    flexShrink: 1,
  },
  actions: {
    flexDirection: "row",
    justifyContent: "flex-end",
    gap: spacing.sm,
    marginTop: spacing.lg,
  },
});
