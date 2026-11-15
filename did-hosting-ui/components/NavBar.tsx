/**
 * Top NavBar — primary navigation + domain switcher.
 *
 * - Logo on the left, primary nav links beside it.
 * - Domain switcher chip (admin-or-multi-domain caller) sits to the right of
 *   the nav links — operators jump between domains without leaving the
 *   current view.
 * - Admin-only entries (`Domains`, `Access`, `Servers`) hidden from
 *   non-admins. Settings stays universal (it holds the caller's passkeys).
 * - Sign out pushed to the far right.
 * - Under `COLLAPSE_BELOW` px the links, the switcher and Sign out fold into
 *   a Menu button, so nothing sits off-screen in a sideways scroll.
 *
 * Why two admin entries for domains and servers: domain ↔ server is
 * many-to-many (a domain can be hosted by multiple servers; a server can host
 * multiple domains), and one page for both made the unassign / purge flow
 * confusing.
 */

import { useEffect, useState } from "react";
import { View, Text, StyleSheet, Pressable, useWindowDimensions } from "react-native";
import { Link, usePathname, type Href } from "expo-router";
import { useAuth } from "./AuthProvider";
import { AffinidiLogo } from "./AffinidiLogo";
import { Button } from "./Button";
import { DomainSwitcher } from "./DomainSwitcher";
import { webAria } from "../lib/a11y";
import { colors, fonts, radii, spacing } from "../lib/theme";

type NavItem = {
  href: Href & string;
  label: string;
  /** When true, hidden from non-admin roles. */
  adminOnly?: boolean;
};

export const NAV_ITEMS: readonly NavItem[] = [
  { href: "/", label: "Dashboard" },
  { href: "/dids", label: "DIDs" },
  { href: "/domains", label: "Domains", adminOnly: true },
  { href: "/acl", label: "Access", adminOnly: true },
  { href: "/servers", label: "Servers", adminOnly: true },
  { href: "/settings", label: "Settings" },
] as const;

/** Below this window width the nav collapses into a menu. */
export const COLLAPSE_BELOW = 700;

export function NavBar() {
  const { isAuthenticated, sessionExpired, role, logout } = useAuth();
  const pathname = usePathname();
  const { width } = useWindowDimensions();
  const [menuOpen, setMenuOpen] = useState(false);
  // 0 = not measured yet (and in tests): lay out wide.
  const collapsed = width > 0 && width < COLLAPSE_BELOW;

  // Navigating closes the menu.
  useEffect(() => setMenuOpen(false), [pathname]);

  if (!isAuthenticated && !sessionExpired) return null;

  const items = NAV_ITEMS.filter((item) => !item.adminOnly || role === "admin");

  const links = items.map((item) => {
    const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
    // Pre-flatten the style arrays. `<Link asChild>` clones the Pressable and
    // forwards its props; an array `style` survives the clone and reaches
    // react-dom's `setValueForStyles`, which crashes the page with "Indexed
    // property setter is not supported." A single object sidesteps it.
    const buttonStyle = StyleSheet.flatten([
      styles.linkButton,
      collapsed && styles.linkButtonStacked,
      active && styles.linkButtonActive,
    ]);
    const textStyle = StyleSheet.flatten([styles.linkText, active && styles.linkTextActive]);
    return (
      <Link key={item.href} href={item.href} asChild>
        <Pressable
          role="link"
          aria-label={item.label}
          {...webAria(active ? { current: "page" } : {})}
          style={buttonStyle}
        >
          <Text style={textStyle}>{item.label}</Text>
        </Pressable>
      </Link>
    );
  });

  const signOut = (
    <Button
      label="Sign out"
      accessibilityLabel="Sign out"
      variant="secondary"
      size="sm"
      onPress={logout}
    />
  );

  return (
    <View style={styles.bar}>
      <View style={styles.inner}>
        <Link href="/" asChild>
          <Pressable style={styles.logoArea} role="link" aria-label="did-hosting home">
            <AffinidiLogo size={22} showWordmark={false} />
          </Pressable>
        </Link>

        {!collapsed && (
          <View style={styles.links} role="navigation" aria-label="Main">
            {links}
          </View>
        )}

        <View style={styles.spacer} />

        {collapsed ? (
          <Button
            label={menuOpen ? "Close menu" : "Menu"}
            variant="secondary"
            size="sm"
            expanded={menuOpen}
            onPress={() => setMenuOpen((o) => !o)}
          />
        ) : (
          <View style={styles.rightCluster}>
            <DomainSwitcher />
            {signOut}
          </View>
        )}
      </View>

      {collapsed && menuOpen && (
        <View style={styles.menu} testID="nav-menu">
          <View role="navigation" aria-label="Main" style={styles.menuLinks}>
            {links}
          </View>
          <View style={styles.menuFooter}>
            <DomainSwitcher />
            {signOut}
          </View>
        </View>
      )}
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
    flexWrap: "wrap",
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
  linkButtonStacked: {
    paddingVertical: spacing.sm,
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
  menu: {
    marginTop: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.border,
    paddingTop: spacing.sm,
    gap: spacing.md,
  },
  menuLinks: {
    gap: 2,
  },
  menuFooter: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    justifyContent: "space-between",
    gap: spacing.sm,
  },
});
