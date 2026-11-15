import { useCallback, useEffect, useRef } from "react";
import { ScrollView, View, StyleSheet } from "react-native";
import { useLocalSearchParams, useRouter, type Href } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { Heading } from "../components/Heading";
import { SignInPanel } from "../components/SignInPanel";
import { safeNextPath } from "../lib/next-path";
import { colors, fonts, radii, spacing } from "../lib/theme";

/**
 * The sign-in page. `?next=` names where to go afterwards — the page the
 * route guard sent the visitor here from — and is honoured only when it is a
 * path on this origin (`safeNextPath`).
 */
export default function Login() {
  const { isAuthenticated } = useAuth();
  const router = useRouter();
  const { next } = useLocalSearchParams<{ next?: string | string[] }>();
  const destination = (safeNextPath(next) ?? "/") as Href;

  // Go where the visitor was headed — once, whether they signed in here or
  // arrived already signed in.
  const left = useRef(false);
  const leave = useCallback(() => {
    if (left.current) return;
    left.current = true;
    router.replace(destination);
  }, [router, destination]);
  useEffect(() => {
    if (isAuthenticated) leave();
  }, [isAuthenticated, leave]);

  return (
    <ScrollView style={styles.scroll} contentContainerStyle={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />
        <Heading style={styles.title}>Sign in</Heading>
        <SignInPanel onSignedIn={leave} />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: {
    flex: 1,
    backgroundColor: colors.bgPrimary,
  },
  container: {
    flexGrow: 1,
    padding: spacing.xl,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.bgPrimary,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    width: "100%",
    maxWidth: 500,
  },
  title: {
    fontSize: 22,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    marginTop: spacing.lg,
    marginBottom: spacing.md,
  },
});
