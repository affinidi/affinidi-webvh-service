import { useCallback, useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  Pressable,
  ActivityIndicator,
  ScrollView,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { ServiceBadges } from "../../components/ServiceBadges";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { showConfirm } from "../../lib/alert";
import type { ControlPlaneConfig, IdentityGeneration } from "../../lib/api";

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

/** How much longer a superseded generation keeps decrypting. */
function remainingLabel(expiresAt: number, now: number): string {
  const left = expiresAt - now;
  if (left <= 0) return "expiring";
  if (left < 60) return `${left}s`;
  if (left < 3600) return `${Math.floor(left / 60)}m`;
  return `${Math.floor(left / 3600)}h ${Math.floor((left % 3600) / 60)}m`;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value}>{value}</Text>
    </View>
  );
}

function Badge({ enabled, label }: { enabled: boolean; label?: string }) {
  return (
    <View style={[styles.badge, enabled ? styles.badgeOn : styles.badgeOff]}>
      <Text style={styles.badgeText}>
        {label ?? (enabled ? "Enabled" : "Disabled")}
      </Text>
    </View>
  );
}

function StatusRow({ label, enabled }: { label: string; enabled: boolean }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Badge enabled={enabled} />
    </View>
  );
}

export default function SettingsPage() {
  const api = useApi();
  const { isAuthenticated } = useAuth();

  const [config, setConfig] = useState<ControlPlaneConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [generations, setGenerations] = useState<IdentityGeneration[]>([]);
  const [identityError, setIdentityError] = useState<string | null>(null);
  /** Id currently being retired, so its button can show progress. */
  const [retiring, setRetiring] = useState<number | null>(null);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));

  const loadGenerations = useCallback(() => {
    api
      .listIdentityGenerations()
      .then((data) => {
        setGenerations(data.generations);
        setIdentityError(null);
      })
      // A deployment with no DID configured has no generations. That is not an
      // error worth showing — the panel simply doesn't render.
      .catch(() => setGenerations([]));
  }, [api]);

  useEffect(() => {
    if (!isAuthenticated) return;
    loadGenerations();
  }, [isAuthenticated, loadGenerations]);

  // The "honoured for" countdown is only meaningful if it actually counts down.
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  /**
   * Retire a superseded generation immediately.
   *
   * Spelled out rather than a bare "are you sure": this drops the key from the
   * running service, so peers still holding the old DID document lose the
   * ability to reach it until their cache expires. That breakage is the point
   * when a key is compromised, but it is not something to trigger by accident.
   */
  const retireGeneration = (g: IdentityGeneration) => {
    showConfirm(
      `Retire generation ${g.id}?`,
      `This stops honouring generation ${g.id} immediately, ahead of its grace period.\n\n` +
        `Messages still encrypted to its key-agreement key will no longer decrypt, and peers ` +
        `whose cached DID document still names that key will be unable to reach this service ` +
        `until their cache expires.\n\n` +
        `Do this if the key is compromised. Otherwise, let the grace period run out.`,
      () => {
        setRetiring(g.id);
        api
          .retireIdentityGeneration(g.id)
          .then(() => {
            setIdentityError(null);
            loadGenerations();
          })
          .catch((e) =>
            setIdentityError(
              e instanceof Error ? e.message : "Failed to retire generation",
            ),
          )
          .finally(() => setRetiring(null));
      },
    );
  };

  useEffect(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    api
      .getConfig()
      .then((data) => {
        setConfig(data);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, isAuthenticated]);

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>Please log in to view settings.</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.buttonPrimary}>
            <Text style={styles.buttonPrimaryText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }

  if (loading) {
    return (
      <View style={styles.containerCenter}>
        <ActivityIndicator color={colors.accent} size="large" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.errorText}>{error}</Text>
      </View>
    );
  }

  if (!config) return null;

  return (
    <ScrollView
      style={styles.scroll}
      contentContainerStyle={styles.container}
    >
      <Text style={styles.title}>Control Plane Settings</Text>

      {/* Identity */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Identity</Text>
        <Row
          label="Control Plane DID"
          value={config.controlDid ?? "Not configured"}
        />
        <Row
          label="Mediator DID"
          value={config.mediatorDid ?? "Not configured"}
        />
        <Row
          label="Control Plane URL"
          value={config.publicUrl ?? "Not configured"}
        />
        {config.didHostingUrl && (
          <Row label="DID Hosting URL" value={config.didHostingUrl} />
        )}
      </View>

      {/* Key generations. Only rendered when there is more than one — a
          service that has never rotated has nothing to say here, and a
          single-row panel would just be noise. */}
      {generations.length > 1 && (
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>Key Generations</Text>
          <Text style={styles.explainer}>
            After a key rotation, peers holding a cached copy of this
            service&apos;s DID document keep encrypting to the old key. Superseded
            generations stay decryptable for a grace period so those messages
            still arrive.
          </Text>

          {generations.map((g) => (
            <View key={g.id} style={styles.generation}>
              <View style={styles.generationHeader}>
                <Text style={styles.generationTitle}>
                  Generation {g.id}
                  {g.current ? " · current" : ""}
                </Text>
                {!g.current && (
                  <Pressable
                    style={styles.buttonDanger}
                    disabled={retiring === g.id}
                    onPress={() => retireGeneration(g)}
                  >
                    <Text style={styles.buttonDangerText}>
                      {retiring === g.id ? "Retiring…" : "Retire now"}
                    </Text>
                  </Pressable>
                )}
              </View>

              <Row label="Key agreement" value={g.key_agreement_kid} />
              {g.expires_at !== null && (
                <Row
                  label="Honoured for"
                  value={remainingLabel(g.expires_at, now)}
                />
              )}
            </View>
          ))}

          {identityError && (
            <Text style={styles.errorText}>{identityError}</Text>
          )}
        </View>
      )}

      {/* Connectivity. `*Enabled` is what config turns on; the badge row
          below is what the control plane's DID document advertises to
          peers. They can disagree — the dashboard's Control Plane card
          spells out the consequences when they do. */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Connectivity</Text>
        <Row label="Listen Address" value={config.listenAddress} />
        <StatusRow label="DIDComm" enabled={config.didcommEnabled} />
        <StatusRow label="TSP" enabled={config.tspEnabled} />
        <StatusRow label="REST API" enabled={config.restApiEnabled} />
        <View style={styles.row}>
          <Text style={styles.label}>Advertised services</Text>
          {config.advertisedServices ? (
            <ServiceBadges
              services={config.advertisedServices}
              emptyLabel="none in DID document"
            />
          ) : (
            <Text style={styles.advertisedUnknown}>
              {config.controlDid ? "DID not resolved" : "no control DID"}
            </Text>
          )}
        </View>
      </View>

      {/* VTA */}
      {(config.vtaUrl || config.vtaDid) && (
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>VTA Integration</Text>
          {config.vtaUrl && <Row label="VTA URL" value={config.vtaUrl} />}
          {config.vtaDid && <Row label="VTA DID" value={config.vtaDid} />}
        </View>
      )}

      {/* Service Registry */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Service Registry</Text>
        <Row
          label="Health Check Interval"
          value={formatDuration(config.healthCheckIntervalSecs)}
        />
        <Row
          label="Configured Instances"
          value={config.configuredInstances.toString()}
        />
      </View>

      {/* Authentication */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Authentication</Text>
        <Row
          label="Access Token Expiry"
          value={formatDuration(config.accessTokenExpiry)}
        />
        <Row
          label="Refresh Token Expiry"
          value={formatDuration(config.refreshTokenExpiry)}
        />
        <Row
          label="Passkey Enrollment TTL"
          value={formatDuration(config.passkeyEnrollmentTtl)}
        />
      </View>

      {/* Storage & Logging */}
      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Storage & Logging</Text>
        <Row label="Data Directory" value={config.dataDir} />
        <Row label="Log Level" value={config.logLevel} />
        <Row label="Log Format" value={config.logFormat} />
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
    padding: spacing.xl,
    paddingBottom: spacing.xxxl,
  },
  containerCenter: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    alignItems: "center",
    justifyContent: "center",
  },
  title: {
    fontSize: 22,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    marginBottom: spacing.xl,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    marginBottom: spacing.lg,
  },
  sectionTitle: {
    fontSize: 16,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
    marginBottom: spacing.md,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  label: {
    fontSize: 13,
    fontFamily: fonts.medium,
    color: colors.textSecondary,
    flex: 1,
  },
  advertisedUnknown: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    fontStyle: "italic",
  },
  value: {
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.textPrimary,
    textAlign: "right",
    flex: 1,
  },
  badge: {
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  badgeOn: {
    backgroundColor: colors.tealMuted,
  },
  badgeOff: {
    backgroundColor: colors.errorBg,
  },
  badgeText: {
    fontSize: 11,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
    textTransform: "uppercase",
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginBottom: spacing.lg,
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 12,
    paddingHorizontal: spacing.xl,
    alignItems: "center",
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontSize: 14,
    fontFamily: fonts.semibold,
  },
  explainer: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    marginBottom: spacing.md,
    lineHeight: 17,
  },
  generation: {
    borderTopWidth: 1,
    borderTopColor: colors.border,
    paddingTop: spacing.md,
    marginTop: spacing.md,
  },
  generationHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: spacing.xs,
  },
  generationTitle: {
    fontSize: 14,
    fontFamily: fonts.semibold,
    color: colors.textPrimary,
  },
  buttonDanger: {
    backgroundColor: colors.errorBg,
    borderRadius: radii.md,
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
  },
  buttonDangerText: {
    color: colors.error,
    fontSize: 12,
    fontFamily: fonts.semibold,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
  },
});
