/**
 * Every way to sign in to the console, in one panel: the login page shows it
 * full-screen, and the "session expired" prompt shows it over the screen the
 * operator was on, so signing back in does not throw their work away.
 */

import { useCallback, useEffect, useState } from "react";
import { View, Text, StyleSheet, type TextStyle, type ViewStyle } from "react-native";
import { useAuth } from "./AuthProvider";
import { AgentNameChips } from "./AgentNameChips";
import { Button } from "./Button";
import { CopyButton } from "./CopyButton";
import { Dialog } from "./Dialog";
import { Field } from "./Field";
import { Heading } from "./Heading";
import { WalletSignIn } from "./WalletSignIn";
import { setAuthMethod, setRefreshToken } from "../lib/api";
import { useApi } from "./ApiProvider";
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

export interface SignInPanelProps {
  /** Called once a session is held (after `useAuth().login`). */
  onSignedIn: () => void;
}

export function SignInPanel({ onSignedIn }: SignInPanelProps) {
  const { login } = useAuth();
  const api = useApi();
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
  const [showLegacyDetail, setShowLegacyDetail] = useState(false);
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

  // M2B.4 — VTA-proxied login. The wallet asks the VTA to sign the sign-in
  // on a vault entry's behalf; the long-term signing key never leaves the VTA.
  const [proxyLoading, setProxyLoading] = useState(false);
  const [proxyError, setProxyError] = useState<string | null>(null);
  const [proxyCandidates, setProxyCandidates] = useState<ProxyVaultEntry[] | null>(null);
  const [proxyPicking, setProxyPicking] = useState(false);

  // The server's own DID, shown so an operator can give it to a wallet that
  // needs a record of this service before it can sign in. The `server/info`
  // Trust Task is the one public read; the row stays hidden until it answers.
  const [serverDid, setServerDid] = useState<string | null>(null);
  // The server's own agent names, rendered beneath the DID: a name is an
  // alias, and the DID stays the thing you paste into a wallet.
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
        // Best-effort. Signing in works without the DID row.
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
      // Keep the renewal credential, so the session can be renewed rather
      // than dying on a fixed timer.
      setRefreshToken(result.refreshToken);
      login(result.accessToken);
      onSignedIn();
    } catch (err: unknown) {
      setPasskeyError(
        errorMessage(
          err,
          "Passkey sign-in failed. If you have not registered a passkey here, ask an administrator for an enrolment link.",
        ),
      );
    } finally {
      setPasskeyLoading(false);
    }
  };

  // The wallet's `login()` returns the same server-issued token the passkey
  // path produces, and binds this browser's session key (`wallet-login.ts`).
  const handleWalletLogin = async () => {
    setWalletLoading(true);
    setWalletError(null);
    try {
      const result = await loginWithWallet();
      setAuthMethod("wallet");
      setRefreshToken(result.refreshToken || null);
      login(result.accessToken);
      onSignedIn();
    } catch (err: unknown) {
      setWalletError(errorMessage(err, "Wallet sign-in failed."));
    } finally {
      setWalletLoading(false);
    }
  };

  // VTA-proxied login. The wallet owns "which identity does this site know me
  // as": it resolves the entry bound to this origin, or asks the operator to
  // pick one on a first sign-in and remembers the answer.
  const handleProxyLoginStart = async () => {
    setProxyLoading(true);
    setProxyError(null);
    try {
      const { entry, bound } = await resolveProxyEntry();
      await runProxyLogin(entry, bound);
    } catch (err: unknown) {
      setProxyError(errorMessage(err, "Your wallet could not find an identity for this site."));
    } finally {
      setProxyLoading(false);
    }
  };

  // Escape hatch, not the default: pick from every identity the wallet holds
  // for this site. Behind an explicit click because it costs a consent prompt
  // that lists the wallet's entries to this page.
  const handleChooseIdentity = async () => {
    setProxyLoading(true);
    setProxyError(null);
    try {
      const candidates = await listProxyCandidates();
      if (candidates.length === 0) {
        setProxyError(
          "Your wallet holds no identity for this site yet. Use “Sign in through your VTA” instead — the wallet will ask which identity to use and remember it.",
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
      setProxyError(errorMessage(err, "Could not list your wallet's identities."));
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
      setRefreshToken(result.refreshToken || null);
      login(result.accessToken);
      onSignedIn();
    } catch (err: unknown) {
      const base = errorMessage(err, "Signing in through your VTA failed.");
      // An identity chosen a moment ago has never been seen here, so a
      // missing access entry is by far the likeliest cause. Name the DID: the
      // operator cannot act on a bare refusal.
      setProxyError(
        justBound
          ? `${base}\n\nThis was the first sign-in as ${entry.principalDid}. If it was refused, an administrator needs to give that DID access.`
          : base,
      );
    } finally {
      setProxyLoading(false);
    }
  };

  const serverDidRow = serverDid ? (
    <View style={styles.serverDidRow}>
      <View style={styles.serverDidColumn}>
        <Text style={styles.serverDidLabel}>This service&apos;s DID</Text>
        <Text style={[styles.serverDidValue, breakAll]} numberOfLines={1} selectable>
          {serverDid}
        </Text>
        {serverNames.length > 0 && (
          <View style={styles.serverNamesRow}>
            <AgentNameChips names={serverNames} didId={serverDid} size="sm" />
          </View>
        )}
        <Text style={styles.serverDidHint}>
          If your wallet asks which service you are signing in to, copy this DID into it.
        </Text>
      </View>
      <CopyButton value={serverDid} accessibilityLabel="Copy this service's DID" />
    </View>
  ) : null;

  return (
    <View>
      <Heading level={2} style={styles.sectionTitle}>
        With your wallet
      </Heading>
      {oobUnavailable ? (
        <Text style={styles.hint}>
          {oobNote ?? "Wallet sign-in with a code is not set up on this server."}
        </Text>
      ) : (
        <WalletSignIn
          serviceDid={serverDid}
          onSignedIn={(accessToken) => {
            login(accessToken);
            onSignedIn();
          }}
          onUnavailable={onOobUnavailable}
        />
      )}
      {serverDidRow}

      <Divider label="or" />

      <Heading level={2} style={styles.sectionTitle}>
        With a passkey
      </Heading>
      <Field
        label="Your DID (optional — only for a security key the browser does not offer)"
        accessibilityLabel="Your DID, to sign in with a security key the browser does not offer"
        placeholder="did:…"
        value={passkeySubject}
        onChangeText={setPasskeySubject}
        onSubmit={() => void handlePasskeyLogin()}
        autoCapitalize="none"
        autoCorrect={false}
      />
      <Button
        label="Sign in with a passkey"
        busy={passkeyLoading}
        busyLabel="Waiting for your passkey…"
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
        <View>
          {/* @deprecated (contract C7): the VTA Wallet extension's SIOPv2 /
          auth/authenticate login and the VTA-proxied SIOP login. Kept for
          wallets that cannot read a sign-in code yet; not deleted until a
          removal date is set. */}
          <Text style={styles.cliHint}>
            These are older ways to sign in, kept for wallets that cannot scan a sign-in code yet.
            If your wallet can, use the code above instead.
          </Text>
          <Button
            label={showLegacyDetail ? "Hide details" : "What is this?"}
            variant="ghost"
            size="sm"
            expanded={showLegacyDetail}
            onPress={() => setShowLegacyDetail((v) => !v)}
            style={styles.whatIsThis}
          />
          {showLegacyDetail && (
            <Text style={styles.cliHint}>
              “Sign in with the wallet extension” signs a SIOPv2 challenge with the did:peer
              identity the VTA Wallet browser extension holds. “Sign in through your VTA” asks your
              VTA to sign a SIOP id_token for a did-self-issued vault entry pinned to this
              service&apos;s DID; the entry&apos;s long-term key never leaves the VTA, and this page
              only sees the short-lived token.
            </Text>
          )}

          {walletAvailable ? (
            <Button
              label="Sign in with the wallet extension"
              variant="secondary"
              busy={walletLoading}
              busyLabel="Waiting for your wallet…"
              onPress={handleWalletLogin}
            />
          ) : (
            <Text style={styles.cliHint}>
              Install the VTA Wallet browser extension to sign in with it.
            </Text>
          )}
          {walletAvailable && walletError && (
            <Text role="alert" style={styles.errorText}>
              {walletError}
            </Text>
          )}

          {proxyAvailable && (
            <>
              <Button
                label="Sign in through your VTA"
                variant="secondary"
                busy={proxyLoading}
                busyLabel="Waiting for your wallet…"
                onPress={handleProxyLoginStart}
                style={{ marginTop: spacing.md }}
              />
              {/* Secondary, and worded as the exception it is: for an
              operator holding more than one identity here. */}
              <Button
                label="Sign in as a different identity…"
                variant="secondary"
                disabled={proxyLoading}
                onPress={handleChooseIdentity}
                style={{ marginTop: spacing.sm }}
              />
              {proxyError && (
                <Text role="alert" style={styles.errorText}>
                  {proxyError}
                </Text>
              )}
            </>
          )}
        </View>
      )}

      <Divider label="need access?" />

      <Text style={styles.cliHint}>
        Ask an administrator for an enrolment link. Open it in this browser to register a passkey,
        then come back here to sign in.
      </Text>

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

/** Choose among the identities the wallet holds for this site. Shows each
 *  one's DID, so the operator knows who they would be acting as. */
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
      title="Choose an identity"
      onClose={onCancel}
      style={{ maxWidth: 600 }}
      actions={<Button label="Cancel" variant="secondary" onPress={onCancel} />}
    >
      <Text style={styles.hint}>
        Your wallet holds more than one identity for this site. Choose which one to sign in as.
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
  whatIsThis: {
    alignSelf: "flex-start",
    marginBottom: spacing.sm,
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
    marginTop: spacing.lg,
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
