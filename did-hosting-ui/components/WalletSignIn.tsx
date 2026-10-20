/**
 * "Sign in with your wallet": wallet sign-in started by a trigger link
 * (`auth/oob/*`, contract C1, C2 and C9).
 *
 * The page shows a trigger link as a code that is also a link: a phone
 * scans it, and a wallet on this device (the browser plugin, or a phone's
 * wallet app when this page is on the phone) opens it by click or tap. The
 * person approves in the wallet; this page then asks "Continue as …?" —
 * unless this browser last continued as that same identity.
 *
 * The code is shown without a click, once the page is visible, and an
 * unclaimed code is renewed when its claim window closes — never from a
 * hidden tab. Whoever scans first holds it, and still needs to be a member
 * and to know the number, so a code on screen is cheap to show.
 *
 * Once claimed, the element showing the number carries it as
 * `data-oob-match-number` beside `data-oob-request-id` (contract C11), for
 * the browser plugin to type it in for the person who clicked the code here.
 *
 * Web only: the starter key is a WebCrypto key and the code is a DOM link.
 * The QR encoder (`qrcode-generator`) sits behind `lib/qr-encoder.ts`.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { Platform, Pressable, StyleSheet, Text, View } from "react-native";

import { api, setAuthMethod, setRefreshToken, setToken } from "../lib/api";
import { getApiBase } from "../lib/api-base";
import {
  configuredLinkHost,
  createSignIn,
  isUnavailable,
  layoutQr,
  localStorageKnownSubject,
  matchNumberHandOff,
  QR_DARK,
  QR_LIGHT,
  type SignInController,
  type SignInState,
} from "../lib/oob-sign-in";
import { defaultQrEncoder } from "../lib/qr-encoder";
import { colors, fonts, radii, spacing } from "../lib/theme";

/** The `ext` namespace the control plane puts this console's tokens under. */
const SESSION_EXT = "com.affinidi.did-hosting";

/** Where the identity this browser last continued as is kept. */
const KNOWN_SUBJECT_KEY = "did-hosting-wallet-signin-known";

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
  // State, not a ref: creating the controller must re-render, or the
  // buttons that need it stay disabled.
  const [c, setController] = useState<SignInController | null>(null);
  const tokens = useRef<Tokens | null>(null);

  useEffect(() => {
    if (Platform.OS !== "web" || !serviceDid) return;
    const c = createSignIn({
      endpoint: `${getApiBase()}/trust-tasks`,
      serviceDid,
      linkHost: configuredLinkHost(),
      knownSubject: localStorageKnownSubject(KNOWN_SUBJECT_KEY),
      onStateChange: setState,
      onRedeemed: (p) => {
        tokens.current = tokensOf(p);
      },
      renew: true,
    });
    setController(c);
    c.startWhenVisible();
    return () => {
      c.destroy();
      setController(null);
    };
  }, [serviceDid]);

  useEffect(() => {
    if (isUnavailable(state)) onUnavailable?.();
  }, [state, onUnavailable]);

  // Signed in, by "Continue" or straight from the redeem for a known
  // identity: hand the tokens over once.
  useEffect(() => {
    if (state.status !== "signedIn") return;
    const t = tokens.current;
    if (!t) return;
    tokens.current = null;
    setAuthMethod("wallet");
    setRefreshToken(t.refreshToken ?? null);
    onSignedIn(t.accessToken);
  }, [state, onSignedIn]);

  if (Platform.OS !== "web") return null;

  const onContinue = () => {
    if (tokens.current) c?.confirm();
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
    c?.startWhenVisible();
  };

  const newCode = (label: string) => (
    <Pressable
      style={[styles.button, (!c || !serviceDid) && styles.disabled]}
      onPress={() => void c?.start()}
      disabled={!c || !serviceDid}
    >
      <Text style={styles.buttonText}>{label}</Text>
    </Pressable>
  );

  switch (state.status) {
    // Idle only until the code is asked for: on mount, or while a hidden tab
    // waits to be visible before it opens a request.
    case "idle":
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
          {/* C11: the number for the browser plugin, on this element only. */}
          <div {...matchNumberHandOff(state)}>
            <Text style={styles.number} accessibilityLabel={`Your number is ${state.matchNumber}`}>
              {state.matchNumber}
            </Text>
          </div>
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
          {newCode("Get a new code")}
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

/** CSS px per module: 5 keeps the longest link (61 modules + quiet zone) under 350 px. */
const QR_MODULE_PX = 5;

/**
 * The code wrapped in `<a href>` (C2, VTI-LNK-086), so a wallet on this
 * device opens it by click, and the same link as a button below it for
 * same-device use. The code is always dark modules on a light quiet zone,
 * whatever the theme, so phones read it in dark mode too.
 */
function TriggerLinkCode({ link }: { link: string }) {
  const qr = useMemo(() => {
    try {
      return layoutQr(link, defaultQrEncoder, QR_MODULE_PX);
    } catch {
      // Too long for a QR code (the starter checks this already): the button still works.
      return null;
    }
  }, [link]);
  return (
    <View style={styles.center}>
      {qr && (
        <a
          href={link}
          rel="noreferrer"
          referrerPolicy="no-referrer"
          style={{ display: "inline-block", lineHeight: 0, background: QR_LIGHT, borderRadius: radii.md }}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            role="img"
            aria-label="Sign-in code. Scan it with your wallet app, or click it to open your wallet on this device."
            width={qr.pixels}
            height={qr.pixels}
            viewBox={`0 0 ${qr.units} ${qr.units}`}
            shapeRendering="crispEdges"
            style={{ display: "block", maxWidth: "100%", height: "auto" }}
          >
            <rect width={qr.units} height={qr.units} fill={QR_LIGHT} />
            <path d={qr.path} fill={QR_DARK} />
          </svg>
        </a>
      )}
      <a href={link} rel="noreferrer" referrerPolicy="no-referrer" style={{ textDecoration: "none" }}>
        <View style={styles.button}>
          <Text style={styles.buttonText}>Open in your wallet</Text>
        </View>
      </a>
    </View>
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
