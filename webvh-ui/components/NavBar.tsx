import { View, Text, StyleSheet, Pressable } from "react-native";
import { Link, usePathname } from "expo-router";
import { useAuth } from "./AuthProvider";
import { AffinidiLogo } from "./AffinidiLogo";
import { colors, fonts, radii, spacing } from "../lib/theme";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard" },
  { href: "/dids", label: "DIDs" },
  { href: "/acl", label: "Access Control" },
  { href: "/settings", label: "\u2699 Settings" },
] as const;

export function NavBar() {
  const { isAuthenticated, logout } = useAuth();
  const pathname = usePathname();

  if (!isAuthenticated) return null;

  return (
    <View style={styles.bar}>
      <View style={styles.inner}>
        <Link href="/" asChild>
          <Pressable style={styles.logoArea}>
            <AffinidiLogo size={22} showWordmark={false} />
          </Pressable>
        </Link>

        <View style={styles.links}>
          {NAV_ITEMS.map((item) => {
            const active =
              item.href === "/"
                ? pathname === "/"
                : pathname.startsWith(item.href);
            return (
              <Link key={item.href} href={item.href as any} asChild>
                <Pressable style={styles.linkButton}>
                  <Text
                    style={[styles.linkText, active && styles.linkTextActive]}
                  >
                    {item.label}
                  </Text>
                </Pressable>
              </Link>
            );
          })}
        </View>

        <View style={styles.spacer} />

        <Pressable style={styles.logoutButton} onPress={logout}>
          <Text style={styles.logoutText}>Logout</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  bar: {
    backgroundColor: colors.bgHeader,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    paddingHorizontal: spacing.xl,
    paddingVertical: spacing.md,
  },
  inner: {
    flexDirection: "row",
    alignItems: "center",
    maxWidth: 960,
    alignSelf: "center",
    width: "100%",
  },
  logoArea: {
    marginRight: spacing.xl,
  },
  links: {
    flexDirection: "row",
    gap: spacing.xs,
  },
  spacer: {
    flex: 1,
  },
  linkButton: {
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderRadius: radii.sm,
  },
  linkText: {
    fontSize: 14,
    fontFamily: fonts.medium,
    color: colors.textTertiary,
  },
  linkTextActive: {
    color: colors.textPrimary,
  },
  logoutButton: {
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderRadius: radii.sm,
  },
  logoutText: {
    fontSize: 14,
    fontFamily: fonts.medium,
    color: colors.error,
  },
});
