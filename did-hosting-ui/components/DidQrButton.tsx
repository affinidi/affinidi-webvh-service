/**
 * A small "QR" button that shows a DID as a QR code, with the DID itself and
 * a copy button, so a phone or wallet can pick it up.
 *
 * Uses the same encoder and layout as wallet sign-in (`lib/qr-encoder.ts`,
 * `layoutQr`): dark on light in both themes, with the 4-module quiet zone.
 */

import { useMemo, useState } from "react";
import { Modal, Pressable, StyleSheet, Text, View } from "react-native";
import * as Clipboard from "expo-clipboard";
import { layoutQr, QR_DARK, QR_LIGHT } from "../lib/oob-sign-in";
import { defaultQrEncoder } from "../lib/qr-encoder";
import { colors, fonts, radii, spacing } from "../lib/theme";

const QR_MODULE_PX = 5;

export function DidQrButton({ did, label }: { did: string; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`Show a QR code for ${label ?? did}`}
        style={({ hovered }: any) => [styles.button, hovered && styles.buttonHover]}
        onPress={(e: any) => {
          // Rows are links; the button must not follow them.
          e?.preventDefault?.();
          e?.stopPropagation?.();
          setOpen(true);
        }}
      >
        <Text style={styles.buttonText}>QR</Text>
      </Pressable>
      {open && <DidQrModal did={did} label={label} onClose={() => setOpen(false)} />}
    </>
  );
}

function DidQrModal({
  did,
  label,
  onClose,
}: {
  did: string;
  label?: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const qr = useMemo(() => {
    try {
      return layoutQr(did, defaultQrEncoder, QR_MODULE_PX);
    } catch {
      return null;
    }
  }, [did]);

  const copy = async () => {
    await Clipboard.setStringAsync(did);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Modal visible transparent animationType="fade" onRequestClose={onClose}>
      <Pressable style={styles.overlay} onPress={onClose}>
        <Pressable
          style={styles.popover}
          onPress={(e) => e.stopPropagation()}
          accessibilityLabel="DID QR code"
        >
          <View style={styles.titleRow}>
            <Text style={styles.title} numberOfLines={1}>
              {label ?? "DID"}
            </Text>
            <Pressable accessibilityRole="button" accessibilityLabel="Close" onPress={onClose}>
              <Text style={styles.close}>✕</Text>
            </Pressable>
          </View>
          {qr ? (
            <View style={styles.qrWrap}>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                role="img"
                aria-label={`QR code for ${did}`}
                width={qr.pixels}
                height={qr.pixels}
                viewBox={`0 0 ${qr.units} ${qr.units}`}
                shapeRendering="crispEdges"
                style={{ display: "block", maxWidth: "100%", height: "auto" }}
              >
                <rect width={qr.units} height={qr.units} fill={QR_LIGHT} />
                <path d={qr.path} fill={QR_DARK} />
              </svg>
            </View>
          ) : (
            <Text style={styles.hint}>This DID is too long for a QR code.</Text>
          )}
          <Text style={styles.did} selectable>
            {did}
          </Text>
          <Pressable accessibilityRole="button" style={styles.copy} onPress={copy}>
            <Text style={styles.copyText}>{copied ? "Copied!" : "Copy DID"}</Text>
          </Pressable>
        </Pressable>
      </Pressable>
    </Modal>
  );
}

const styles = StyleSheet.create({
  button: {
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.sm,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 2,
    paddingHorizontal: spacing.sm,
  },
  buttonHover: {
    borderColor: colors.accent,
  },
  buttonText: {
    fontSize: 11,
    fontFamily: fonts.semibold,
    color: colors.textSecondary,
    letterSpacing: 0.4,
  },
  overlay: {
    flex: 1,
    backgroundColor: colors.overlay,
    alignItems: "center",
    justifyContent: "center",
    padding: spacing.lg,
  },
  popover: {
    width: "100%",
    maxWidth: 420,
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    gap: spacing.md,
    alignItems: "center",
  },
  titleRow: {
    flexDirection: "row",
    alignItems: "center",
    alignSelf: "stretch",
    gap: spacing.md,
  },
  title: {
    flex: 1,
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
  },
  close: {
    fontSize: 16,
    color: colors.textTertiary,
    paddingHorizontal: spacing.xs,
  },
  qrWrap: {
    backgroundColor: QR_LIGHT,
    borderRadius: radii.md,
    lineHeight: 0,
  } as any,
  did: {
    fontSize: 12,
    fontFamily: fonts.mono,
    color: colors.success,
    textAlign: "center",
    wordBreak: "break-all",
  } as any,
  hint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
  copy: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 10,
    paddingHorizontal: spacing.xl,
  },
  copyText: {
    color: colors.textOnAccent,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
});
