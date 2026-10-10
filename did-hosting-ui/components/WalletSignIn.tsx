/**
 * "Sign in with your wallet": wallet sign-in started by a trigger link
 * (`auth/oob/*`, contract C1, C2 and C9).
 *
 * The page shows a trigger link as a code that is also a link: a phone
 * scans it, and a wallet on this device (the browser plugin, or a phone's
 * wallet app when this page is on the phone) opens it by click or tap. The
 * person approves in the wallet; this page then asks "Continue as …?".
 *
 * Web only: the starter key is a WebCrypto key and the code is a DOM link.
 */

import { useEffect, useRef, useState } from "react";
import { Platform, Pressable, StyleSheet, Text, View } from "react-native";

import { api, setAuthMethod, setRefreshToken, setToken } from "../lib/api";
import { getApiBase } from "../lib/api-base";
import {
  configuredLinkHost,
  createSignIn,
  isUnavailable,
  renderQrSvg,
  type QrEncoder,
  type SignInController,
  type SignInState,
} from "../lib/oob-sign-in";
import { colors, fonts, radii, spacing } from "../lib/theme";

/**
 * The QR encoder. None is bundled: the UI has no QR library among its
 * dependencies, and adding one is a separate decision. Until then the code is
 * shown as its link only (same-device sign-in works; scanning does not).
 * TODO: set to a level-M byte-mode encoder (rp-sdk uses qrcode-generator 2.0.4).
 */
const QR_ENCODER: QrEncoder | null = null;

/** The `ext` namespace the control plane puts this console's tokens under. */
const SESSION_EXT = "com.affinidi.did-hosting";

interface Tokens {
  accessToken: string;
  refreshToken?: string;
}

function tokensOf(payload: Record<string, unknown>): Tokens | null {
  const ext = payload.ext as Record<string, { tokens?: Tokens }> | undefined;
  const t = ext?.[SESSION_EXT]?.tokens;
  return t && typeof t.accessToken === "string" ? t : null;
}

export function WalletSignIn({
  serviceDid,
  onSignedIn,
  onUnavailable,
}: {
  serviceDid: string | null;
  /** Called with the access token after "Continue". */
  onSignedIn: (accessToken: string) => void;
  /** Called when this server does not offer the sign-in ({@link isUnavailable}),
   *  so the page can fall back to its other login methods. */
  onUnavailable?: () => void;
}) {
  const [state, setState] = useState<SignInState>({ status: "idle" });
  const controller = useRef<SignInController | null>(null);
  const tokens = useRef<Tokens | null>(null);

  useEffect(() => {
    if (Platform.OS !== "web" || !serviceDid) return;
    const c = createSignIn({
      endpoint: `${getApiBase()}/trust-tasks`,
      serviceDid,
      linkHost: configuredLinkHost(),
      onStateChange: setState,
      onRedeemed: (p) => {
        tokens.current = tokensOf(p);
      },
    });
    controller.current = c;
    return () => c.destroy();
  }, [serviceDid]);

  useEffect(() => {
    if (isUnavailable(state)) onUnavailable?.();
  }, [state, onUnavailable]);

  if (Platform.OS !== "web") return null;
  const c = controller.current;

  const onContinue = () => {
    const t = tokens.current;
    if (!c || !t) return;
    c.confirm();
    setAuthMethod("wallet");
    setRefreshToken(t.refreshToken ?? null);
    onSignedIn(t.accessToken);
  };

  // "Not me": end the session at once. `api.logout` revokes it with the
  // session key before the key is dropped.
  const onNotMe = async () => {
    const t = tokens.current;
    tokens.current = null;
    if (t) {
      setToken(t.accessToken);
      setRefreshToken(t.refreshToken ?? null);
      await api.logout();
    }
    await c?.notMe();
  };

  const newCode = (label = "Show sign-in code") => (
    <Pressable
      style={[styles.button, (!c || !serviceDid) && styles.disabled]}
      onPress={() => void c?.start()}
      disabled={!c || !serviceDid}
    >
      <Text style={styles.buttonText}>{label}</Text>
    </Pressable>
  );

  switch (state.status) {
    case "idle":
      return (
        <View>
          <Text style={styles.hint}>
            Scan a code with your wallet app, or click it if your wallet is on this device.
          </Text>
          {newCode()}
        </View>
      );
    case "starting":
      return <Text style={styles.hint}>Getting a sign-in code…</Text>;
    case "waiting":
      return (
        <View style={styles.center}>
          {state.codeVisible ? (
            <TriggerLinkCode link={state.link} />
          ) : (
            // C9: hidden, not cancelled; the request is still being polled.
            <Text style={styles.hint}>The code is hidden while this tab is in the background.</Text>
          )}
          <Text style={styles.hint}>
            Scan with your wallet, or click the code. It expires at{" "}
            {state.expiresAt.toLocaleTimeString()}.
          </Text>
          <Pressable style={styles.linkButton} onPress={() => void c?.cancel()}>
            <Text style={styles.linkButtonText}>Cancel</Text>
          </Pressable>
        </View>
      );
    case "claimed":
      return (
        <View style={styles.center}>
          <Text style={styles.hint}>Approve on your phone. Your number is</Text>
          <Text style={styles.number} accessibilityLabel={`Your number is ${state.matchNumber}`}>
            {state.matchNumber}
          </Text>
          <Pressable style={styles.linkButton} onPress={() => void c?.cancel()}>
            <Text style={styles.linkButtonText}>Cancel</Text>
          </Pressable>
        </View>
      );
    case "confirm":
      return (
        <View>
          <Text style={styles.confirm}>
            Continue as <Text style={styles.bold}>{state.displayName ?? state.subject}</Text>?
          </Text>
          {state.displayName && state.displayName !== state.subject && (
            <Text style={styles.mono} numberOfLines={1}>
              {state.subject}
            </Text>
          )}
          <Pressable style={styles.button} onPress={onContinue}>
            <Text style={styles.buttonText}>Continue</Text>
          </Pressable>
          <Pressable style={styles.linkButton} onPress={() => void onNotMe()}>
            <Text style={styles.linkButtonText}>Not me</Text>
          </Pressable>
        </View>
      );
    case "signedIn":
      return <Text style={styles.hint}>Signed in.</Text>;
    case "declined":
    case "cancelled":
    case "expired": {
      const msg = {
        declined: "The sign-in was declined.",
        cancelled: "The sign-in was cancelled.",
        expired: "The code expired.",
      }[state.status];
      return (
        <View>
          <Text style={styles.hint}>{msg}</Text>
          {newCode("Show a new code")}
        </View>
      );
    }
    case "error":
      return (
        <View>
          <Text style={styles.errorText}>{state.message}</Text>
          {newCode("Try again")}
        </View>
      );
  }
}

/**
 * The code wrapped in `<a href>` (C2, VTI-LNK-086), so a wallet on this
 * device opens it by click. Without an encoder, the link alone.
 */
function TriggerLinkCode({ link }: { link: string }) {
  if (QR_ENCODER) {
    return (
      <a
        href={link}
        rel="noreferrer"
        referrerPolicy="no-referrer"
        aria-label="Sign-in code. Scan it with your wallet, or click it to open your wallet."
        // The SVG is built from our own encoder output and fixed strings only.
        dangerouslySetInnerHTML={{ __html: renderQrSvg(link, QR_ENCODER, 5) }}
        style={{ display: "inline-block", lineHeight: 0, background: "#ffffff" }}
      />
    );
  }
  return (
    <a href={link} rel="noreferrer" referrerPolicy="no-referrer" style={{ textDecoration: "none" }}>
      <View style={styles.button}>
        <Text style={styles.buttonText}>Open in your wallet</Text>
      </View>
    </a>
  );
}

const styles = StyleSheet.create({
  center: { alignItems: "center", gap: spacing.sm },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginBottom: spacing.md,
    lineHeight: 20,
    textAlign: "center",
  },
  number: { fontSize: 48, fontFamily: fonts.bold, color: colors.textPrimary, letterSpacing: 4 },
  confirm: { fontSize: 18, fontFamily: fonts.regular, color: colors.textPrimary, marginBottom: spacing.sm },
  bold: { fontFamily: fonts.bold },
  mono: {
    fontFamily: "ui-monospace, monospace",
    fontSize: 12,
    color: colors.textSecondary,
    marginBottom: spacing.md,
  },
  button: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 14,
    paddingHorizontal: spacing.lg,
    alignItems: "center",
  },
  buttonText: { color: colors.textOnAccent, fontSize: 16, fontFamily: fonts.semibold },
  disabled: { opacity: 0.5 },
  linkButton: { paddingVertical: spacing.sm, alignItems: "center" },
  linkButtonText: { color: colors.accent, fontSize: 14, fontFamily: fonts.medium },
  errorText: {
    color: colors.error,
    fontSize: 13,
    fontFamily: fonts.regular,
    marginBottom: spacing.md,
    textAlign: "center",
  },
});
