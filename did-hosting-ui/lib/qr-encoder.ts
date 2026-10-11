/**
 * The default QR encoder: `qrcode-generator` (MIT, no dependencies), the same
 * library and settings as `@openvtc/rp-sdk/browser`'s `defaultQrEncoder`.
 *
 * It is imported only here, behind the {@link QrEncoder} interface, so another
 * library can replace it without touching the page or the renderer.
 */

import qrcode from "qrcode-generator";

import type { QrEncoder } from "./oob-sign-in";

/** Automatic version, error-correction level M, byte mode (C1). */
export const defaultQrEncoder: QrEncoder = (text) => {
  const qr = qrcode(0, "M");
  qr.addData(text, "Byte");
  qr.make();
  const size = qr.getModuleCount();
  return { size, isDark: (r, c) => qr.isDark(r, c) };
};
