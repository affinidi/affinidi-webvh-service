/**
 * Top NavBar — primary navigation + domain switcher.
 *
 * v0.7 redesign:
 * - Logo on the left, primary nav links beside it.
 * - Domain switcher chip (admin-or-multi-domain caller) sits to
 *   the right of the nav links — operators jump between domains
 *   without leaving the current view.
 * - Admin-only entries (`Domains`, `Servers`) hidden from
 *   non-admins. Settings stays universal.
 * - Logout pushed to the far right.
 *
 * Why two admin entries: domain ↔ server is a many-to-many
 * relationship (a domain can be hosted by multiple servers; a
 * server can host multiple domains). Folding both views into one
 * page made the unassign / purge flow confusing; two pages with
 * focused jobs is clearer.
 */

import { View, Text, StyleSheet, Pressable, ScrollView } from "react-native";
import { Link, usePathname } from "expo-router";
import { useAuth } from "./AuthProvider";
import { AffinidiLogo } from "./AffinidiLogo";
import { DomainSwitcher } from "./DomainSwitcher";
import { colors, fonts, radii, spacing } from "../lib/theme";

type NavItem = {
  href: string;
  label: string;
  /** When true, hidden from non-admin roles. */
  adminOnly?: boolean;
};

const NAV_ITEMS: readonly NavItem[] = [
  { href: "/", label: "Dashboard" },
  { href: "/dids", label: "DIDs" },
  { href: "/domains", label: "Domains", adminOnly: true },
  { href: "/acl", label: "Access" },
  { href: "/servers", label: "Servers", adminOnly: true },
  { href: "/settings", label: "Settings" },
] as const;

export function NavBar() {
  const { isAuthenticated, role, logout } = useAuth();
  const pathname = usePathname();

  if (!isAuthenticated) return null;

  const items = NAV_ITEMS.filter(
    (item) => !item.adminOnly || role === "admin",
  );

  return (
    <View style={styles.bar}>
      <View style={styles.inner}>
        <Link href="/" asChild>
          <Pressable
            style={styles.logoArea}
            accessibilityRole="link"
            accessibilityLabel="did-hosting home"
          >
            <AffinidiLogo size={22} showWordmark={false} />
          </Pressable>
        </Link>

        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.links}
        >
          {items.map((item) => {
            const active =
              item.href === "/"
                ? pathname === "/"
                : pathname.startsWith(item.href);
            return (
              <Link key={item.href} href={item.href as any} asChild>
                <Pressable
                  accessibilityRole="link"
                  accessibilityState={{ selected: active }}
                  style={[styles.linkButton, active && styles.linkButtonActive]}
                >
                  <Text
                    style={[
                      styles.linkText,
                      active && styles.linkTextActive,
                    ]}
                  >
                    {item.label}
                  </Text>
                </Pressable>
              </Link>
            );
          })}
        </ScrollView>

        <View style={styles.spacer} />

        <View style={styles.rightCluster}>
          <DomainSwitcher />
          <Pressable
            style={styles.logoutButton}
            onPress={logout}
            accessibilityRole="button"
            accessibilityLabel="Log out"
          >
            <Text style={styles.logoutText}>Logout</Text>
          </Pressable>
        </View>
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
    maxWidth: 1200,
    alignSelf: "center",
    width: "100%",
    gap: spacing.md,
  },
  logoArea: {
    marginRight: spacing.md,
  },
  links: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.xs,
  },
  spacer: {
    flex: 1,
  },
  rightCluster: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
  },
  linkButton: {
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
    borderRadius: radii.sm,
  },
  linkButtonActive: {
    backgroundColor: colors.bgTertiary,
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
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
    borderRadius: radii.sm,
  },
  logoutText: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.error,
  },
});
