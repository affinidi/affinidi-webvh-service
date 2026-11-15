import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { StyleSheet, Text, View } from "react-native";

import {
  CONFIRMED,
  TOAST_MS,
  dismissToast,
  getFeedbackState,
  settleConfirm,
  subscribeFeedback,
  type ConfirmChoice,
  type PendingConfirm,
  type Toast,
} from "../lib/feedback";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { Button, type ButtonHandle } from "./Button";
import { Dialog } from "./Dialog";
import { Field } from "./Field";

/**
 * Renders what `lib/feedback.ts` asks for: the open confirmation dialog and
 * the toasts. Mounted once, in the root layout.
 */
export function FeedbackHost() {
  const { toasts, confirm } = useSyncExternalStore(
    subscribeFeedback,
    getFeedbackState,
    getFeedbackState,
  );
  return (
    <>
      {confirm && <ConfirmDialog key={confirm.id} request={confirm} />}
      {toasts.length > 0 && (
        <View style={styles.toasts} pointerEvents="box-none">
          {toasts.map((t) => (
            <ToastView key={t.id} toast={t} />
          ))}
        </View>
      )}
    </>
  );
}

/**
 * One confirmation: title, body, an optional list of what is affected, an
 * optional type-to-confirm field, and explicitly labelled actions. Focus
 * starts on Cancel, so Enter or Space on arrival never performs the action.
 */
export function ConfirmDialog({ request }: { request: PendingConfirm }) {
  const [typed, setTyped] = useState("");
  const cancelRef = useRef<ButtonHandle>(null);
  const destructive = request.destructive ?? true;
  const choices: ConfirmChoice[] = request.choices ?? [
    {
      value: CONFIRMED,
      label: request.confirmLabel ?? "Confirm",
      variant: destructive ? "danger" : "primary",
      requiresTyping: !!request.typeToConfirm,
    },
  ];
  const typedOk = !request.typeToConfirm || typed.trim() === request.typeToConfirm;

  useEffect(() => {
    // After the modal's own focus handling has run.
    const focus = () => (cancelRef.current as unknown as HTMLElement | null)?.focus?.();
    focus();
    const t = setTimeout(focus, 0);
    return () => clearTimeout(t);
  }, []);

  const cancel = () => settleConfirm(request.id, null);

  return (
    <Dialog
      visible
      title={request.title}
      onClose={cancel}
      hideCloseButton
      testID="confirm-dialog"
      actions={
        <View style={styles.actions}>
          <Button
            buttonRef={cancelRef}
            label={request.cancelLabel ?? "Cancel"}
            variant="secondary"
            onPress={cancel}
          />
          {choices.map((c) => (
            <Button
              key={c.value}
              label={c.label}
              variant={c.variant ?? "danger"}
              disabled={c.requiresTyping ? !typedOk : false}
              onPress={() => settleConfirm(request.id, c.value)}
            />
          ))}
        </View>
      }
    >
      <Text style={styles.body}>{request.body}</Text>
      {request.details && request.details.length > 0 && (
        <View style={styles.details} role="list">
          {request.details.map((d) => (
            <Text key={d} role="listitem" style={styles.detail} numberOfLines={1}>
              • {d}
            </Text>
          ))}
        </View>
      )}
      {request.typeToConfirm ? (
        <Field
          label={`Type ${request.typeToConfirm} to confirm`}
          value={typed}
          onChangeText={setTyped}
          autoCapitalize="none"
          autoCorrect={false}
          autoComplete="off"
          style={styles.typeField}
        />
      ) : null}
    </Dialog>
  );
}

function ToastView({ toast }: { toast: Toast }) {
  useEffect(() => {
    if (toast.kind === "error") return;
    const t = setTimeout(() => dismissToast(toast.id), TOAST_MS);
    return () => clearTimeout(t);
  }, [toast.id, toast.kind]);
  const tone =
    toast.kind === "error"
      ? styles.toastError
      : toast.kind === "success"
        ? styles.toastSuccess
        : styles.toastInfo;
  return (
    <View role={toast.kind === "error" ? "alert" : "status"} style={[styles.toast, tone]}>
      <View style={styles.toastText}>
        <Text style={styles.toastTitle}>{toast.title}</Text>
        {toast.message ? <Text style={styles.toastMessage}>{toast.message}</Text> : null}
      </View>
      <Button
        label="×"
        accessibilityLabel={`Dismiss: ${toast.title}`}
        variant="ghost"
        size="sm"
        onPress={() => dismissToast(toast.id)}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  actions: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "flex-end",
    gap: spacing.sm,
  },
  body: {
    fontFamily: fonts.regular,
    fontSize: 14,
    lineHeight: 20,
    color: colors.textSecondary,
  },
  details: {
    marginTop: spacing.md,
    maxHeight: 200,
    overflow: "scroll",
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.sm,
    padding: spacing.sm,
  },
  detail: {
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.textPrimary,
    paddingVertical: 2,
  },
  typeField: {
    marginTop: spacing.md,
    marginBottom: 0,
  },
  toasts: {
    position: "absolute",
    right: spacing.lg,
    bottom: spacing.lg,
    left: spacing.lg,
    alignItems: "flex-end",
    gap: spacing.sm,
    zIndex: 1000,
  },
  toast: {
    flexDirection: "row",
    alignItems: "flex-start",
    width: "100%",
    maxWidth: 420,
    borderRadius: radii.md,
    borderWidth: 1,
    paddingVertical: spacing.sm,
    paddingLeft: spacing.md,
    paddingRight: spacing.xs,
    backgroundColor: colors.bgSecondary,
  },
  toastSuccess: { borderColor: colors.success },
  toastError: { borderColor: colors.error, backgroundColor: colors.errorBg },
  toastInfo: { borderColor: colors.border },
  toastText: { flex: 1, paddingVertical: spacing.xs },
  toastTitle: {
    fontFamily: fonts.semibold,
    fontSize: 14,
    color: colors.textPrimary,
  },
  toastMessage: {
    fontFamily: fonts.regular,
    fontSize: 13,
    lineHeight: 18,
    color: colors.textSecondary,
    marginTop: 2,
  },
});
