/**
 * A small "QR" button that shows a DID as a QR code, with the DID itself and
 * a copy button, so a phone or wallet can pick it up.
 *
 * Uses the same encoder and layout as wallet sign-in (`lib/qr-encoder.ts`,
 * `layoutQr`): dark on light in both themes, with the 4-module quiet zone.
 */

import { useMemo, useState } from "react";
import { StyleSheet, Text, View, type TextStyle } from "react-native";
import { layoutQr, QR_DARK, QR_LIGHT } from "../lib/oob-sign-in";
import { defaultQrEncoder } from "../lib/qr-encoder";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { Button } from "./Button";
import { CopyButton } from "./CopyButton";
import { Dialog } from "./Dialog";

const QR_MODULE_PX = 5;

export function DidQrButton({ did, label }: { did: string; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button
        label="QR"
        variant="secondary"
        size="sm"
        accessibilityLabel={`Show a QR code for ${label ?? did}`}
        onPress={() => setOpen(true)}
      />
      {open && <DidQrDialog did={did} label={label} onClose={() => setOpen(false)} />}
    </>
  );
}

function DidQrDialog({
  did,
  label,
  onClose,
}: {
  did: string;
  label?: string;
  onClose: () => void;
}) {
  const qr = useMemo(() => {
    try {
      return layoutQr(did, defaultQrEncoder, QR_MODULE_PX);
    } catch {
      return null;
    }
  }, [did]);

  return (
    <Dialog visible title={label ?? "DID"} onClose={onClose} style={styles.panel}>
      <View style={styles.body}>
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
        <Text style={[styles.did, breakAll]} selectable>
          {did}
        </Text>
        <CopyButton
          value={did}
          label="Copy DID"
          copiedLabel="Copied!"
          variant="primary"
          size="md"
          accessibilityLabel="Copy DID"
        />
      </View>
    </Dialog>
  );
}

/** RN-Web only — not in React Native's style types. */
const breakAll = { wordBreak: "break-all" } as TextStyle;

const styles = StyleSheet.create({
  panel: {
    maxWidth: 420,
  },
  body: {
    gap: spacing.md,
    alignItems: "center",
  },
  qrWrap: {
    backgroundColor: QR_LIGHT,
    borderRadius: radii.md,
    overflow: "hidden",
  },
  did: {
    fontSize: 12,
    fontFamily: fonts.mono,
    color: colors.success,
    textAlign: "center",
  },
  hint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
  },
});
