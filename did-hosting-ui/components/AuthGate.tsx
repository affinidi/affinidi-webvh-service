import { useEffect, useState, type ReactNode } from "react";
import { ActivityIndicator, ScrollView, StyleSheet, Text, View } from "react-native";
import { usePathname, useRouter, type Href } from "expo-router";

import { currentPath, loginHref } from "../lib/next-path";
import { guardDecision } from "../lib/route-guard";
import { colors, fonts, radii, spacing } from "../lib/theme";
import { AffinidiLogo } from "./AffinidiLogo";
import { useAuth } from "./AuthProvider";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { SignInPanel } from "./SignInPanel";

/**
 * The route guard (see `lib/route-guard.ts`), wrapped around the navigator.
 *
 * The navigator itself always renders — the router needs it mounted to
 * navigate — and the guard covers it: with the splash while the session is
 * restored or a redirect is on its way, and with a "session expired" prompt
 * that leaves the screen beneath it, and whatever the operator had typed into
 * it, in place.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const { isAuthenticated, restored, sessionExpired } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const decision = guardDecision({ pathname, restored, isAuthenticated, sessionExpired });

  useEffect(() => {
    if (decision === "redirect") router.replace(loginHref(currentPath(pathname)) as Href);
  }, [decision, pathname, router]);

  return (
    <View style={styles.root}>
      {children}
      {(decision === "splash" || decision === "redirect") && <Splash />}
      {decision === "expired" && <SessionExpiredPrompt />}
    </View>
  );
}

export function Splash() {
  return (
    <View style={styles.splash} testID="splash">
      <AffinidiLogo size={48} />
      <Text style={styles.splashText}>Decentralized Identity Hosting</Text>
      <ActivityIndicator color={colors.accent} aria-label="Loading" style={styles.spinner} />
    </View>
  );
}

/**
 * A banner over the current screen: the session has ended, nothing on the
 * screen has been thrown away, and signing in again — in a dialog, without
 * leaving the page — picks up where the operator left off.
 */
export function SessionExpiredPrompt() {
  const { logout } = useAuth();
  const [signingIn, setSigningIn] = useState(false);
  return (
    <>
      <View role="alert" style={styles.banner} testID="session-expired">
        <View style={styles.bannerText}>
          <Text style={styles.bannerTitle}>Session expired — sign in again</Text>
          <Text style={styles.bannerBody}>
            Your session ended. Anything you have not saved is still on this page; sign in again to
            carry on where you left off.
          </Text>
        </View>
        <View style={styles.bannerActions}>
          <Button label="Sign in again" onPress={() => setSigningIn(true)} />
          <Button label="Sign out" variant="secondary" onPress={logout} />
        </View>
      </View>
      <Dialog
        visible={signingIn}
        title="Sign in again"
        onClose={() => setSigningIn(false)}
        style={styles.dialog}
      >
        <ScrollView style={styles.dialogScroll}>
          <SignInPanel onSignedIn={() => setSigningIn(false)} />
        </ScrollView>
      </Dialog>
    </>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
  splash: {
    ...StyleSheet.absoluteFill,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgPrimary,
    zIndex: 100,
  },
  splashText: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginTop: spacing.md,
    letterSpacing: 0.5,
  },
  spinner: {
    marginTop: spacing.lg,
  },
  banner: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    zIndex: 100,
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    gap: spacing.md,
    padding: spacing.md,
    backgroundColor: colors.bgSecondary,
    borderBottomWidth: 2,
    borderBottomColor: colors.warning,
  },
  bannerText: {
    flex: 1,
    minWidth: 240,
  },
  bannerTitle: {
    fontFamily: fonts.semibold,
    fontSize: 15,
    color: colors.warning,
  },
  bannerBody: {
    fontFamily: fonts.regular,
    fontSize: 13,
    color: colors.textSecondary,
    marginTop: 2,
  },
  bannerActions: {
    flexDirection: "row",
    gap: spacing.sm,
  },
  dialog: {
    maxWidth: 520,
    maxHeight: "90%",
    borderRadius: radii.lg,
  },
  dialogScroll: {
    flexGrow: 0,
  },
});
