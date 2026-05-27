import { useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import { useRouter } from "expo-router";
import { useAuth } from "../components/AuthProvider";
import { AffinidiLogo } from "../components/AffinidiLogo";
import {
  api,
  clearSessionPrincipalDid,
  setAuthMethod,
  setSessionPrincipalDid,
} from "../lib/api";
import { getPasskeyCredential } from "../lib/passkey";
import { colors, fonts, radii, spacing } from "../lib/theme";
import {
  isWalletAvailable,
  isWalletProxyAvailable,
  listProxyCandidates,
  loginWithWallet,
  loginWithWalletProxy,
  type ProxyLoginViz,
  type ProxyVaultEntry,
} from "../lib/wallet";

export default function Login() {
  const { isAuthenticated, login } = useAuth();
  const router = useRouter();
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [walletLoading, setWalletLoading] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);
  const walletAvailable = isWalletAvailable();
  const proxyAvailable = isWalletProxyAvailable();

  // M2B.4 — VTA-proxied login.
  // The user picks a did-self-issued vault entry pinned to this RP's
  // DID; the wallet asks the VTA to mint a SIOP id_token on the
  // entry's behalf; the page posts it to /auth/. The long-term
  // signing key never leaves the VTA.
  const [proxyLoading, setProxyLoading] = useState(false);
  const [proxyError, setProxyError] = useState<string | null>(null);
  const [proxyCandidates, setProxyCandidates] = useState<
    ProxyVaultEntry[] | null
  >(null);
  const [proxyPicking, setProxyPicking] = useState(false);
  const [proxyViz, setProxyViz] = useState<ProxyLoginViz | null>(null);
  // Opt-in flow visualization. Off by default — the visualization is
  // a demo aid, not the everyday auth UX. Persists across reloads so
  // a presenter can flip it on once for a session. Stored as a string
  // (`"1"` / `"0"`) to keep the JSON.parse boundary trivial.
  const VIZ_PREF_KEY = "didhosting:proxyLoginViz";
  const [showProxyViz, setShowProxyViz] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(VIZ_PREF_KEY) === "1";
  });
  const toggleShowProxyViz = (next: boolean) => {
    setShowProxyViz(next);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(VIZ_PREF_KEY, next ? "1" : "0");
    }
  };

  // Fetch the server's own DID so the operator can see it on the
  // login page — they need it when granting wallet access (the DID
  // is what the wallet pins a did-self-issued vault entry to). The
  // /api/server-info endpoint is unauthenticated and cached at the
  // api-client layer; mounting the login page is cheap. `null` is
  // a legitimate response when the operator hasn't configured a
  // server_did yet; we skip rendering the row in that case rather
  // than showing "(unset)" — operators who haven't configured it
  // don't need a Copy button.
  const [serverDid, setServerDid] = useState<string | null>(null);
  const [copiedServerDid, setCopiedServerDid] = useState(false);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const info = await api.serverInfo();
        if (!cancelled) setServerDid(info.server_did);
      } catch {
        // Best-effort. The login page works without the DID row.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleCopyServerDid = async () => {
    if (!serverDid) return;
    await Clipboard.setStringAsync(serverDid);
    setCopiedServerDid(true);
    setTimeout(() => setCopiedServerDid(false), 2000);
  };

  const handlePasskeyLogin = async () => {
    setPasskeyLoading(true);
    setPasskeyError(null);
    try {
      const { auth_id, options } = await api.passkeyLoginStart();
      const credential = await getPasskeyCredential(options);
      const result = await api.passkeyLoginFinish(auth_id, credential);
      setAuthMethod("passkey");
      login(result.access_token);
      router.replace("/");
    } catch (err: any) {
      setPasskeyError(
        err?.message || "Passkey login failed. Passkeys may not be configured."
      );
    } finally {
      setPasskeyLoading(false);
    }
  };

  // The wallet's `login()` returns the SAME server-issued JWT shape the
  // passkey path produces (both come out of did-hosting-control's
  // `/api/auth/`), so we route into `useAuth().login(...)` identically.
  // Passkey login stays as-is — this is additive.
  const handleWalletLogin = async () => {
    setWalletLoading(true);
    setWalletError(null);
    try {
      const result = await loginWithWallet();
      setAuthMethod("wallet");
      // Holder login — session DID is the wallet's holder DID. Trust-task
      // signing should NOT route via vault/sign-trust-task; clear any
      // stale principal-DID hint from a previous proxy-login session.
      clearSessionPrincipalDid();
      login(result.accessToken);
      router.replace("/");
    } catch (err: any) {
      setWalletError(err?.message || "Wallet login failed.");
    } finally {
      setWalletLoading(false);
    }
  };

  // M2B.4 — VTA-proxied login. Two-stage flow because the user may
  // have multiple did-self-issued entries pinned to this RP and we
  // want them to pick which one.
  const handleProxyLoginStart = async () => {
    setProxyLoading(true);
    setProxyError(null);
    setProxyViz(null);
    try {
      const candidates = await listProxyCandidates();
      if (candidates.length === 0) {
        setProxyError(
          "No did-self-issued vault entry is pinned to this RP. Open the wallet, add an entry with this RP's DID as a target, then try again.",
        );
        return;
      }
      if (candidates.length === 1) {
        await runProxyLogin(candidates[0]!);
      } else {
        setProxyCandidates(candidates);
        setProxyPicking(true);
      }
    } catch (err: any) {
      setProxyError(err?.message || "Could not enumerate proxy entries.");
    } finally {
      setProxyLoading(false);
    }
  };

  const runProxyLogin = async (entry: ProxyVaultEntry) => {
    setProxyLoading(true);
    setProxyError(null);
    setProxyPicking(false);
    try {
      const outcome = await loginWithWalletProxy(entry);
      setAuthMethod("wallet");
      // Proxy login — session is authenticated as the entry's
      // principalDid (the SIOP id_token's iss/sub). Subsequent
      // trust-task signing MUST sign as this DID, not the wallet's
      // holder; record it so api.ts's signTrustTask path threads
      // `asDid` through to the wallet's vault/sign-trust-task call.
      // `principalDid` is optional on ProxyVaultEntry for forward-compat,
      // but `listProxyCandidates` already filters out entries without
      // one — only entries that round-trip with a DID reach this path.
      setSessionPrincipalDid(entry.principalDid!);
      login(outcome.result.accessToken);
      // When the operator has enabled the flow visualization, stash
      // it and let the modal hold the redirect. Otherwise (the
      // default), go straight to the dashboard — the visualization
      // is a demo aid, not the everyday UX.
      if (showProxyViz) {
        setProxyViz(outcome.viz);
      } else {
        router.replace("/");
      }
    } catch (err: any) {
      setProxyError(err?.message || "VTA-proxied login failed.");
    } finally {
      setProxyLoading(false);
    }
  };

  // Redirect to the dashboard whenever auth state is "logged in" — UNLESS
  // the proxy-login visualization modal is showing, in which case the
  // user is mid-demo and the modal owns the "Continue" → redirect step.
  //
  // This used to be an `if (isAuthenticated) return <Authenticated />`
  // early-return that rendered a holding-page card. That had two
  // problems: (a) nothing in the app linked to it (the dashboard is
  // where authenticated users belong), and (b) `runProxyLogin` calls
  // `login()` BEFORE setting the viz state, so the holding page
  // rendered first and the viz modal — which lives in the login
  // form's return tree — never got to mount. Replacing with a
  // useEffect makes the "viz first, dashboard second" ordering work
  // and eliminates the dead screen.
  useEffect(() => {
    if (isAuthenticated && !proxyViz) {
      router.replace("/");
    }
  }, [isAuthenticated, proxyViz, router]);

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <AffinidiLogo size={36} />
        <Text style={styles.title}>Login</Text>
        <Text style={styles.hint}>
          Use your registered passkey to authenticate with this server.
        </Text>

        {serverDid && (
          <View style={styles.serverDidRow}>
            <View style={styles.serverDidColumn}>
              <Text style={styles.serverDidLabel}>This server</Text>
              <Text style={styles.serverDidValue} numberOfLines={1}>
                {serverDid}
              </Text>
              <Text style={styles.serverDidHint}>
                Grant access to this DID in your wallet to enable proxied SIOP login.
              </Text>
            </View>
            <Pressable style={styles.copyButton} onPress={() => void handleCopyServerDid()}>
              <Text style={styles.copyButtonText}>
                {copiedServerDid ? "Copied!" : "Copy"}
              </Text>
            </Pressable>
          </View>
        )}

        <Pressable
          style={[styles.button, passkeyLoading && styles.disabled]}
          onPress={handlePasskeyLogin}
          disabled={passkeyLoading}
        >
          <Text style={styles.buttonText}>
            {passkeyLoading ? "Authenticating..." : "Login with Passkey"}
          </Text>
        </Pressable>

        {passkeyError && (
          <Text style={styles.errorText}>{passkeyError}</Text>
        )}

        <View style={styles.divider}>
          <View style={styles.dividerLine} />
          <Text style={styles.dividerText}>or</Text>
          <View style={styles.dividerLine} />
        </View>

        {walletAvailable && (
          <Pressable
            style={walletLoading ? [styles.secondaryButton, styles.disabled] : styles.secondaryButton}
            onPress={handleWalletLogin}
            disabled={walletLoading}
          >
            <Text style={styles.secondaryButtonText}>
              {walletLoading ? "Authenticating…" : "Login with VTA Wallet"}
            </Text>
          </Pressable>
        )}
        {walletAvailable && walletError && (
          <Text style={styles.errorText}>{walletError}</Text>
        )}
        {!walletAvailable && (
          <Text style={styles.cliHint}>
            Install the VTA Wallet browser extension to sign in with your did:peer
            identity (no passkey required).
          </Text>
        )}

        {proxyAvailable && (
          <>
            <View style={[styles.divider, { marginTop: spacing.md }]}>
              <View style={styles.dividerLine} />
              <Text style={styles.dividerText}>via VTA proxy</Text>
              <View style={styles.dividerLine} />
            </View>
            <Pressable
              style={proxyLoading ? [styles.secondaryButton, styles.disabled] : styles.secondaryButton}
              onPress={handleProxyLoginStart}
              disabled={proxyLoading}
            >
              <Text style={styles.secondaryButtonText}>
                {proxyLoading ? "Authenticating…" : "Login via VTA-proxied SIOP"}
              </Text>
            </Pressable>
            <Text style={styles.cliHint}>
              VTA mints a SIOP id_token on a vault entry's behalf. The
              entry's long-term signing key never leaves the VTA — the
              page only sees the short-lived id_token.
            </Text>
            <Pressable
              onPress={() => toggleShowProxyViz(!showProxyViz)}
              style={styles.vizToggleRow}
              accessibilityRole="checkbox"
              accessibilityState={{ checked: showProxyViz }}
            >
              <Text style={styles.vizToggleBox}>{showProxyViz ? "☑" : "☐"}</Text>
              <Text style={styles.vizToggleLabel}>
                Show flow visualization (demo)
              </Text>
            </Pressable>
            {proxyError && <Text style={styles.errorText}>{proxyError}</Text>}
          </>
        )}

        <View style={styles.divider}>
          <View style={styles.dividerLine} />
          <Text style={styles.dividerText}>need access?</Text>
          <View style={styles.dividerLine} />
        </View>

        <Text style={styles.cliHint}>
          Ask a server admin to send you an enrollment link. Open it in this
          browser to register a passkey, then return here to log in.
        </Text>
      </View>

      {proxyPicking && proxyCandidates && (
        <ProxyCandidatePicker
          candidates={proxyCandidates}
          onCancel={() => setProxyPicking(false)}
          onPick={(entry) => void runProxyLogin(entry)}
        />
      )}

      {proxyViz && (
        <ProxyLoginVisualization
          viz={proxyViz}
          onContinue={() => router.replace("/")}
        />
      )}
    </View>
  );
}

// ─── M2B.4 picker UI ───
// Inline modal that lets the user choose among multiple did-self-issued
// vault entries pinned to this RP's DID. Renders the principal DID +
// last-used timestamp so the user knows which identity they'd be acting
// as.
function ProxyCandidatePicker({
  candidates,
  onCancel,
  onPick,
}: {
  candidates: ProxyVaultEntry[];
  onCancel: () => void;
  onPick: (entry: ProxyVaultEntry) => void;
}) {
  return (
    <View style={styles.modalBackdrop}>
      <View style={[styles.card, { maxWidth: 600 }]}>
        <Text style={styles.title}>Pick a proxy identity</Text>
        <Text style={styles.hint}>
          Multiple did-self-issued vault entries are pinned to this RP. Pick
          which one to log in as.
        </Text>
        {candidates.map((c) => (
          <Pressable
            key={c.id}
            style={[styles.secondaryButton, { marginBottom: spacing.sm }]}
            onPress={() => onPick(c)}
          >
            <Text style={styles.secondaryButtonText}>{c.label}</Text>
            <Text style={[styles.cliHint, { marginTop: 4 }]}>{c.principalDid}</Text>
          </Pressable>
        ))}
        <Pressable style={styles.dangerButton} onPress={onCancel}>
          <Text style={styles.dangerButtonText}>Cancel</Text>
        </Pressable>
      </View>
    </View>
  );
}

// ─── M2B.4 visualization ───
// Shows the user what just happened: timeline of the three round-trips
// (RP /auth/challenge → VTA proxy-login → RP /auth/), the decoded SIOP
// id_token claims, the SessionBlob summary, total elapsed time. The
// "Continue" button drives the redirect into the authenticated app.
function ProxyLoginVisualization({
  viz,
  onContinue,
}: {
  viz: ProxyLoginViz;
  onContinue: () => void;
}) {
  return (
    <View style={styles.modalBackdrop}>
      <View style={[styles.card, { maxWidth: 720, maxHeight: "90%" }]}>
        <Text style={styles.title}>VTA-proxied login flow</Text>
        <Text style={styles.hint}>
          Authenticated in {viz.totalMs} ms. The long-term signing key for{" "}
          <Text style={styles.mono}>{viz.chosenEntry.principalDid}</Text>{" "}
          never left the VTA — the wallet only ever saw the short-lived id_token.
        </Text>

        <View style={styles.vizScroll}>
          {viz.steps.map((s, i) => (
            <View key={i} style={styles.vizStep}>
              <View style={styles.vizStepHeader}>
                <Text style={styles.vizStepLabel}>{s.label}</Text>
                <Text style={styles.vizStepDuration}>{s.durationMs} ms</Text>
              </View>
              <Text style={styles.vizStepDesc}>{s.description}</Text>
            </View>
          ))}
          {viz.idToken && (
            <View style={styles.vizStep}>
              <Text style={styles.vizStepLabel}>SIOP id_token claims</Text>
              <Text style={[styles.mono, styles.vizCodeBlock]}>
                {JSON.stringify(viz.idToken.payload, null, 2)}
              </Text>
            </View>
          )}
          {viz.sessionBlob && (
            <View style={styles.vizStep}>
              <Text style={styles.vizStepLabel}>SessionBlob summary</Text>
              <Text style={styles.vizStepDesc}>
                sessionId: <Text style={styles.mono}>{viz.sessionBlob.sessionId}</Text>
                {"\n"}expiresAt: <Text style={styles.mono}>{viz.sessionBlob.expiresAt}</Text>
                {viz.sessionBlob.bindOrigin && (
                  <>
                    {"\n"}bindOrigin:{" "}
                    <Text style={styles.mono}>{viz.sessionBlob.bindOrigin}</Text>
                  </>
                )}
                {"\n"}{viz.sessionBlob.headerCount} header(s),{" "}
                {viz.sessionBlob.cookieCount} cookie(s)
              </Text>
            </View>
          )}
        </View>

        <Pressable style={styles.button} onPress={onContinue}>
          <Text style={styles.buttonText}>Continue</Text>
        </Pressable>
      </View>
    </View>
  );
}

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
    // RN-Web only — break long DIDs gracefully when the truncation
    // ellipsis isn't applied (e.g. when zoomed in).
    wordBreak: "break-all",
  } as any,
  serverDidHint: {
    marginTop: 4,
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 16,
  },
  copyButton: {
    backgroundColor: colors.accent,
    borderRadius: radii.sm,
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
  },
  copyButtonText: {
    fontSize: 12,
    fontFamily: fonts.medium,
    color: colors.bgPrimary,
  },
  button: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 14,
    alignItems: "center",
  },
  disabled: {
    opacity: 0.5,
  },
  dangerButton: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.error,
    paddingVertical: 14,
    alignItems: "center",
    marginTop: spacing.lg,
  },
  dangerButtonText: {
    color: colors.error,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
  buttonText: {
    color: colors.textOnAccent,
    fontSize: 16,
    fontFamily: fonts.semibold,
  },
  // Visual distinction from the primary passkey button: outlined rather than
  // filled, so the two options read as peers without one looking like the
  // canonical answer.
  secondaryButton: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.accent,
    paddingVertical: 14,
    alignItems: "center",
  },
  secondaryButtonText: {
    color: colors.accent,
    fontSize: 16,
    fontFamily: fonts.semibold,
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
  vizToggleRow: {
    flexDirection: "row" as const,
    alignItems: "center" as const,
    gap: spacing.xs,
    marginTop: -spacing.xs,
    marginBottom: spacing.sm,
  },
  vizToggleBox: {
    fontSize: 14,
    color: colors.textSecondary,
  },
  vizToggleLabel: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  mono: {
    fontFamily: "ui-monospace, monospace",
    fontSize: 12,
    color: colors.textSecondary,
  },
  modalBackdrop: {
    position: "absolute" as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: "rgba(0,0,0,0.4)",
    alignItems: "center",
    justifyContent: "center",
    padding: spacing.lg,
  },
  vizScroll: {
    marginTop: spacing.md,
    marginBottom: spacing.lg,
    gap: spacing.md,
  },
  vizStep: {
    padding: spacing.md,
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.bgPrimary,
    gap: spacing.xs,
  },
  vizStepHeader: {
    flexDirection: "row" as const,
    justifyContent: "space-between" as const,
    alignItems: "center" as const,
  },
  vizStepLabel: {
    fontFamily: fonts.semibold,
    fontSize: 13,
    color: colors.textPrimary,
  },
  vizStepDuration: {
    fontSize: 11,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
  },
  vizStepDesc: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    lineHeight: 18,
  },
  vizCodeBlock: {
    padding: spacing.sm,
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.sm,
    fontSize: 11,
    lineHeight: 16,
  },
});
