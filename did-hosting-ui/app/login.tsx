import { useCallback, useEffect, useState } from "react";
import { View, Text, StyleSheet, type TextStyle, type ViewStyle } from "react-native";
import { useRouter } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import { AgentNameChips } from "../components/AgentNameChips";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { Dialog } from "../components/Dialog";
import { Field } from "../components/Field";
import { Heading } from "../components/Heading";
import { WalletSignIn } from "../components/WalletSignIn";
import { setAuthMethod, setRefreshToken } from "../lib/api";
import { useApi } from "../components/ApiProvider";
import { errorMessage } from "../lib/errors";
import { getPasskeyCredential } from "../lib/passkey";
import { fetchSignInReadiness, notSetUpNote, offersWalletSignIn } from "../lib/sign-in-readiness";
import { colors, fonts, radii, spacing } from "../lib/theme";
import {
  isWalletAvailable,
  isWalletProxyAvailable,
  listProxyCandidates,
  loginWithWallet,
  loginWithWalletProxy,
  resolveProxyEntry,
  type ProxyVaultEntry,
} from "../lib/wallet";

export default function Login() {
  const { isAuthenticated, login } = useAuth();
  const api = useApi();
  const router = useRouter();
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  // Optional: name your DID so a security key that the browser does not
  // offer by itself (one enrolled as non-discoverable) is asked for by id.
  const [passkeySubject, setPasskeySubject] = useState("");
  const [walletLoading, setWalletLoading] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);
  const walletAvailable = isWalletAvailable();
  const proxyAvailable = isWalletProxyAvailable();
  // Contract C7: the SIOPv2 / extension logins are kept, deprecated, behind
  // "Using an older wallet?". Wallet sign-in with a trigger link is first.
  const [showLegacy, setShowLegacy] = useState(false);
  // A control plane without the sign-in configured (no service DID or public
  // URL) answers 503: drop the new flow and show the older options open, so
  // the page offers exactly what it did before.
  const [oobUnavailable, setOobUnavailable] = useState(false);
  const onOobUnavailable = useCallback(() => {
    setOobUnavailable(true);
    setShowLegacy(true);
  }, []);
  // The server's self-check of its own DID document: when it lacks the
  // services wallets need, the sign-in would only end in "This code can't be
  // used", so say why and fall back the same way. Anything but a clear
  // "not set up" (including a failed check) keeps the sign-in offered.
  const [oobNote, setOobNote] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    void fetchSignInReadiness().then((r) => {
      if (cancelled || offersWalletSignIn(r)) return;
      setOobNote(notSetUpNote(r));
      onOobUnavailable();
    });
    return () => {
      cancelled = true;
    };
  }, [onOobUnavailable]);

  // M2B.4 — VTA-proxied login.
  // The user picks a did-self-issued vault entry pinned to this RP's
  // DID; the wallet asks the VTA to mint a SIOP id_token on the
  // entry's behalf; the page posts it to /auth/. The long-term
  // signing key never leaves the VTA.
  const [proxyLoading, setProxyLoading] = useState(false);
  const [proxyError, setProxyError] = useState<string | null>(null);
  const [proxyCandidates, setProxyCandidates] = useState<ProxyVaultEntry[] | null>(null);
  const [proxyPicking, setProxyPicking] = useState(false);

  // Fetch the server's own DID so the operator can see it on the
  // login page — they need it when granting wallet access (the DID
  // is what the wallet pins a did-self-issued vault entry to). The
  // `server/info` Trust Task is the one public read, and is cached at the
  // api-client layer; mounting the login page is cheap. The row stays
  // hidden until the read succeeds (a control plane with no DID cannot
  // answer it).
  const [serverDid, setServerDid] = useState<string | null>(null);
  // The server's own agent names, if it serves any. Same request as the DID —
  // no extra round-trip — and rendered beneath it, because a name is an alias
  // and the DID stays the thing you paste into a wallet.
  const [serverNames, setServerNames] = useState<string[]>([]);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const info = await api.serverInfo();
        if (!cancelled) {
          setServerDid(info.serviceDid);
          setServerNames(info.serviceNames);
        }
      } catch {
        // Best-effort. The login page works without the DID row.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api]);

  const handlePasskeyLogin = async () => {
    if (passkeyLoading) return;
    setPasskeyLoading(true);
    setPasskeyError(null);
    try {
      const { authId, options } = await api.passkeyLoginStart(passkeySubject.trim() || undefined);
      const credential = await getPasskeyCredential({ publicKey: options });
      const result = await api.passkeyLoginFinish(authId, credential);
      setAuthMethod("passkey");
      // Keep the renewal credential. Every login path hands one back and
      // all three used to drop it, which is why a session could not be
      // renewed and died on a fixed timer.
      setRefreshToken(result.refreshToken);
      login(result.accessToken);
      router.replace("/");
    } catch (err: unknown) {
      setPasskeyError(errorMessage(err, "Passkey login failed. Passkeys may not be configured."));
    } finally {
      setPasskeyLoading(false);
    }
  };

  // The wallet's `login()` returns the SAME server-issued JWT shape the
  // passkey path produces, so we route into `useAuth().login(...)`
  // identically. Like the passkey path, it binds this browser's session key,
  // which signs the session's calls from here on (`wallet-login.ts`).
  const handleWalletLogin = async () => {
    setWalletLoading(true);
    setWalletError(null);
    try {
      const result = await loginWithWallet();
      setAuthMethod("wallet");
      setRefreshToken(result.refreshToken || null);
      login(result.accessToken);
      router.replace("/");
    } catch (err: unknown) {
      setWalletError(errorMessage(err, "Wallet login failed."));
    } finally {
      setWalletLoading(false);
    }
  };

  // VTA-proxied login. The wallet owns "which identity does this RP know me
  // as": it resolves the entry bound to this origin, or asks the operator to
  // pick a persona on a first sign-in and remembers the answer. The flow this
  // replaces enumerated every entry pinned to this RP just to find one, and on
  // a fresh wallet returned nothing and dead-ended with "add an entry, then
  // try again".
  const handleProxyLoginStart = async () => {
    setProxyLoading(true);
    setProxyError(null);
    try {
      const { entry, bound } = await resolveProxyEntry();
      await runProxyLogin(entry, bound);
    } catch (err: unknown) {
      setProxyError(errorMessage(err, "Could not resolve an identity for this site."));
    } finally {
      setProxyLoading(false);
    }
  };

  // Escape hatch, not the default: pick from every entry pinned to this RP.
  // Kept because an operator may hold more than one persona here, and the
  // wallet's answer is the one bound to this origin. Behind an explicit click
  // because reaching it costs a consent prompt that enumerates the vault to
  // this page.
  const handleChooseIdentity = async () => {
    setProxyLoading(true);
    setProxyError(null);
    try {
      const candidates = await listProxyCandidates();
      if (candidates.length === 0) {
        setProxyError(
          "No did-self-issued vault entry is pinned to this RP. Use the main proxy sign-in instead — the wallet will ask which identity to use and remember it.",
        );
        return;
      }
      if (candidates.length === 1) {
        await runProxyLogin(candidates[0]!);
      } else {
        setProxyCandidates(candidates);
        setProxyPicking(true);
      }
    } catch (err: unknown) {
      setProxyError(errorMessage(err, "Could not enumerate proxy entries."));
    } finally {
      setProxyLoading(false);
    }
  };

  const runProxyLogin = async (entry: ProxyVaultEntry, justBound = false) => {
    setProxyLoading(true);
    setProxyError(null);
    setProxyPicking(false);
    try {
      const result = await loginWithWalletProxy(entry);
      setAuthMethod("wallet");
      // The session is the entry's principal DID (the id_token's iss/sub),
      // and it is bound to the session key the login generated, which
      // signs as that principal from here on (`trust-task.ts`).
      setRefreshToken(result.refreshToken || null);
      login(result.accessToken);
      router.replace("/");
    } catch (err: unknown) {
      const base = errorMessage(err, "VTA-proxied login failed.");
      // A persona bound a moment ago has never been seen by this RP, so its
      // ACL is by far the likeliest cause. Name the DID: the operator cannot
      // act on a bare refusal, and the DID is not on screen anywhere else.
      setProxyError(
        justBound
          ? `${base}\n\nThis was the first sign-in as ${entry.principalDid}. If the RP refused it, that DID needs to be on its access list.`
          : base,
      );
    } finally {
      setProxyLoading(false);
    }
  };

  // Redirect to the dashboard whenever auth state is "logged in": the
  // dashboard is where authenticated users belong.
  useEffect(() => {
    if (isAuthenticated) {
      router.replace("/");
    }
  }, [isAuthenticated, router]);

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />
        <Heading style={styles.title}>Login</Heading>

        {oobUnavailable ? (
          <Text style={styles.hint}>
            {oobNote ?? "Wallet sign-in with a code is not set up on this server."}
          </Text>
        ) : (
          <>
            <Heading level={2} style={styles.sectionTitle}>
              Sign in with your wallet
            </Heading>
            <WalletSignIn
              serviceDid={serverDid}
              onSignedIn={(accessToken) => {
                login(accessToken);
                router.replace("/");
              }}
              onUnavailable={onOobUnavailable}
            />
          </>
        )}

        <Divider label="or" />

        {serverDid && (
          <View style={styles.serverDidRow}>
            <View style={styles.serverDidColumn}>
              <Text style={styles.serverDidLabel}>This server</Text>
              <Text style={[styles.serverDidValue, breakAll]} numberOfLines={1} selectable>
                {serverDid}
              </Text>
              {serverNames.length > 0 && (
                <View style={styles.serverNamesRow}>
                  <AgentNameChips names={serverNames} didId={serverDid} size="sm" />
                </View>
              )}
              <Text style={styles.serverDidHint}>
                Your wallet needs a record of this DID to sign in here.
              </Text>
            </View>
            <CopyButton value={serverDid} accessibilityLabel="Copy this server's DID" />
          </View>
        )}

        <Field
          label="Your DID (optional; for a security key that is not offered)"
          accessibilityLabel="Your DID, to sign in with a security key the browser does not offer"
          placeholder="did:…"
          value={passkeySubject}
          onChangeText={setPasskeySubject}
          onSubmit={() => void handlePasskeyLogin()}
          autoCapitalize="none"
          autoCorrect={false}
        />
        <Button
          label="Login with Passkey"
          busy={passkeyLoading}
          busyLabel="Authenticating..."
          onPress={handlePasskeyLogin}
        />

        {passkeyError && (
          <Text role="alert" style={styles.errorText}>
            {passkeyError}
          </Text>
        )}

        <Button
          label={showLegacy ? "Hide older wallet options" : "Using an older wallet?"}
          variant="ghost"
          size="sm"
          expanded={showLegacy}
          onPress={() => setShowLegacy(!showLegacy)}
          style={styles.legacyToggle}
        />

        {showLegacy && (
          <>
            {/* @deprecated (contract C7): the VTA Wallet extension's SIOPv2 /
            auth/authenticate login and the VTA-proxied SIOP login. Kept for
            wallets that cannot read a sign-in code yet; not deleted until a
            removal date is set. */}
            <Text style={styles.cliHint}>
              These sign-in methods are deprecated. Use “Sign in with your wallet” above if your
              wallet supports it.
            </Text>

            {walletAvailable && (
              <Button
                label="Login with VTA Wallet"
                variant="secondary"
                busy={walletLoading}
                busyLabel="Authenticating…"
                onPress={handleWalletLogin}
              />
            )}
            {walletAvailable && walletError && (
              <Text role="alert" style={styles.errorText}>
                {walletError}
              </Text>
            )}
            {!walletAvailable && (
              <Text style={styles.cliHint}>
                Install the VTA Wallet browser extension to sign in with your did:peer identity (no
                passkey required).
              </Text>
            )}

            {proxyAvailable && (
              <>
                <Divider label="via VTA proxy" style={{ marginTop: spacing.md }} />
                <Button
                  label="Login via VTA-proxied SIOP"
                  variant="secondary"
                  busy={proxyLoading}
                  busyLabel="Authenticating…"
                  onPress={handleProxyLoginStart}
                />
                {/* Secondary, and worded as the exception it is. The button above
                uses whichever identity the wallet has bound to this site; this
                is for an operator holding more than one here, and it costs a
                consent prompt that enumerates the vault to this page. */}
                <Button
                  label="Login as a different identity…"
                  variant="secondary"
                  disabled={proxyLoading}
                  onPress={handleChooseIdentity}
                  style={{ marginTop: spacing.sm }}
                />
                <Text style={styles.cliHint}>
                  VTA mints a SIOP id_token on a vault entry&apos;s behalf. The entry&apos;s
                  long-term signing key never leaves the VTA — the page only sees the short-lived
                  id_token.
                </Text>
                {proxyError && (
                  <Text role="alert" style={styles.errorText}>
                    {proxyError}
                  </Text>
                )}
              </>
            )}
          </>
        )}

        <Divider label="need access?" />

        <Text style={styles.cliHint}>
          Ask a server admin to send you an enrollment link. Open it in this browser to register a
          passkey, then return here to log in.
        </Text>
      </View>

      <ProxyCandidatePicker
        visible={proxyPicking && proxyCandidates !== null}
        candidates={proxyCandidates ?? []}
        onCancel={() => setProxyPicking(false)}
        onPick={(entry) => void runProxyLogin(entry)}
      />
    </View>
  );
}

function Divider({ label, style }: { label: string; style?: ViewStyle }) {
  return (
    <View style={[styles.divider, style]}>
      <View style={styles.dividerLine} />
      <Text style={styles.dividerText}>{label}</Text>
      <View style={styles.dividerLine} />
    </View>
  );
}

// ─── M2B.4 picker UI ───
// A dialog that lets the user choose among multiple did-self-issued vault
// entries pinned to this RP's DID. Renders the principal DID so the user
// knows which identity they'd be acting as.
function ProxyCandidatePicker({
  visible,
  candidates,
  onCancel,
  onPick,
}: {
  visible: boolean;
  candidates: ProxyVaultEntry[];
  onCancel: () => void;
  onPick: (entry: ProxyVaultEntry) => void;
}) {
  return (
    <Dialog
      visible={visible}
      title="Pick a proxy identity"
      onClose={onCancel}
      style={{ maxWidth: 600 }}
      actions={<Button label="Cancel" variant="danger" onPress={onCancel} />}
    >
      <Text style={styles.hint}>
        Multiple did-self-issued vault entries are pinned to this RP. Pick which one to log in as.
      </Text>
      {candidates.map((c) => (
        <Button
          key={c.id}
          variant="secondary"
          accessibilityLabel={`${c.label}, ${c.principalDid}`}
          onPress={() => onPick(c)}
          style={styles.candidate}
        >
          <View>
            <Text style={styles.candidateLabel}>{c.label}</Text>
            <Text style={[styles.cliHint, { marginTop: 4 }]}>{c.principalDid}</Text>
          </View>
        </Button>
      ))}
    </Dialog>
  );
}

/** RN-Web only — break long DIDs gracefully when the truncation ellipsis isn't
 *  applied (e.g. when zoomed in). Not in React Native's style types. */
const breakAll = { wordBreak: "break-all" } as TextStyle;

const styles = StyleSheet.create({
  container: {
    flex: 1,
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
  sectionTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.sm,
  },
  legacyToggle: {
    marginTop: spacing.lg,
    alignSelf: "center",
  },
  candidate: {
    marginBottom: spacing.sm,
    justifyContent: "flex-start",
  },
  candidateLabel: {
    color: colors.textPrimary,
    fontSize: 15,
    fontFamily: fonts.semibold,
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginBottom: spacing.lg,
    lineHeight: 20,
  },
  serverDidRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    padding: spacing.sm,
    marginBottom: spacing.lg,
    backgroundColor: colors.bgTertiary,
    borderRadius: radii.sm,
  },
  serverDidColumn: {
    flex: 1,
    minWidth: 0, // lets the DID truncate inside the row
  },
  serverDidLabel: {
    fontSize: 11,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
    marginBottom: 2,
  },
  serverDidValue: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textPrimary,
  },
  serverNamesRow: {
    marginTop: spacing.sm,
  },
  serverDidHint: {
    marginTop: 4,
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 16,
  },
  divider: {
    flexDirection: "row",
    alignItems: "center",
    marginTop: spacing.xxl,
    marginBottom: spacing.lg,
  },
  dividerLine: {
    flex: 1,
    height: 1,
    backgroundColor: colors.border,
  },
  dividerText: {
    color: colors.textTertiary,
    fontSize: 13,
    fontFamily: fonts.regular,
    marginHorizontal: spacing.md,
  },
  errorText: {
    color: colors.error,
    fontSize: 13,
    fontFamily: fonts.regular,
    marginTop: spacing.md,
    textAlign: "center",
  },
  cliHint: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    lineHeight: 19,
    marginBottom: spacing.sm,
  },
});
