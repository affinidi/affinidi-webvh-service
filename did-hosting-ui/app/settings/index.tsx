import { useState } from "react";
import { View, Text, StyleSheet, ActivityIndicator, ScrollView } from "react-native";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { Button } from "../../components/Button";
import { Countdown } from "../../components/Countdown";
import { Heading } from "../../components/Heading";
import { RequireAuth } from "../../components/RequireAuth";
import { ServiceBadges } from "../../components/ServiceBadges";
import { AgentNameChips } from "../../components/AgentNameChips";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { confirm, notify } from "../../lib/feedback";
import { ErrorWithRetry } from "../../components/QueryState";
import { errorMessage } from "../../lib/errors";
import { useTrustTaskMutation, useTrustTaskQuery } from "../../lib/query";
import { QK } from "../../lib/query-keys";
import { formatDuration } from "../../lib/time";
import { useAgentNames } from "../../lib/use-agent-names";
import type { IdentityGeneration } from "../../lib/api";
import { PasskeysCard } from "../../components/PasskeysCard";

/** A configured interval, compact: "15m", "7d". */
function interval(seconds: number): string {
  return formatDuration(seconds, { style: "compact" });
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value}>{value}</Text>
    </View>
  );
}

/**
 * A [`Row`] whose value is a DID, with any agent names it serves as chips
 * beneath it.
 *
 * Under the DID, never above, per `AgentNameChips`: a name is an alias, and
 * the DID stays the authoritative line. With no names this renders exactly as
 * a plain `Row` did, which is the common case.
 */
function DidRow({
  label,
  did,
  names,
}: {
  label: string;
  did: string | null | undefined;
  names: string[];
}) {
  if (!did) return <Row label={label} value="Not configured" />;
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <View style={styles.didValue}>
        <Text style={styles.value}>{did}</Text>
        {names.length > 0 && (
          <View style={styles.didValueNames}>
            <AgentNameChips names={names} didId={did} size="sm" />
          </View>
        )}
      </View>
    </View>
  );
}

function Badge({ enabled, label }: { enabled: boolean; label?: string }) {
  return (
    <View style={[styles.badge, enabled ? styles.badgeOn : styles.badgeOff]}>
      <Text style={styles.badgeText}>{label ?? (enabled ? "Enabled" : "Disabled")}</Text>
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
  return (
    <RequireAuth purpose="view settings">
      <Settings />
    </RequireAuth>
  );
}

function Settings() {
  const api = useApi();
  const { role } = useAuth();
  // Settings shows control-plane topology (mediator/VTA DIDs, listen address,
  // registry, TTLs) — the same operator data the backend now gates behind
  // an admin (`server/config`, `identity/list`). Non-admins get
  // an explanatory panel instead of a blank page or a 403 error box.
  const isAdmin = role === "admin";

  // Shared with the dashboard and the service overview (`QK.serverConfig`).
  const {
    data: config,
    loading,
    error,
    refetch,
  } = useTrustTaskQuery(QK.serverConfig, ({ background }) => api.getConfig({ background }), {
    enabled: isAdmin,
  });

  // Called unconditionally, above the early returns, and tolerant of the
  // nulls it sees while `config` is still loading — it re-requests when the
  // set of DIDs actually changes, not on every render.
  const agentNames = useAgentNames([config?.controlDid, config?.mediatorDid, config?.vtaDid]);

  // A deployment with no DID configured answers with no generations, and
  // the panel simply doesn't render. A failed read is said, with a retry.
  const generationsQuery = useTrustTaskQuery(
    QK.identityGenerations,
    () => api.listIdentityGenerations().then((d) => d.generations),
    { enabled: isAdmin },
  );
  const generations: IdentityGeneration[] = generationsQuery.data ?? [];
  const retire = useTrustTaskMutation((id: number) => api.retireIdentityGeneration(id), {
    invalidates: [QK.identityGenerations],
  });
  /** Id currently being retired, so its button can show progress. */
  const [retiring, setRetiring] = useState<number | null>(null);

  /**
   * Retire a superseded generation immediately.
   *
   * Spelled out rather than a bare "are you sure": this drops the key from the
   * running service, so peers still holding the old DID document lose the
   * ability to reach it until their cache expires. That breakage is the point
   * when a key is compromised, but it is not something to trigger by accident.
   */
  const retireGeneration = async (g: IdentityGeneration) => {
    const ok = await confirm({
      title: `Retire generation ${g.id}?`,
      body:
        `This stops honouring generation ${g.id} immediately, ahead of its grace period.\n\n` +
        `Messages still encrypted to its key-agreement key will no longer decrypt, and peers ` +
        `whose cached DID document still names that key will be unable to reach this service ` +
        `until their cache expires.\n\n` +
        `Do this if the key is compromised. Otherwise, let the grace period run out.`,
      confirmLabel: `Retire generation ${g.id}`,
    });
    if (!ok) return;
    setRetiring(g.id);
    retire
      .mutate(g.id)
      .then(() => notify("success", `Generation ${g.id} retired`))
      .catch(() => {
        // Shown below from `retire.error`.
      })
      .finally(() => setRetiring(null));
  };
  const identityError = retire.error
    ? errorMessage(retire.error, "Failed to retire generation")
    : null;

  // Everything below "My Passkeys" is control-plane topology, admin only.
  // Passkeys are the caller's own account, regardless of role.
  if (!isAdmin) {
    return (
      <ScrollView style={styles.scroll} contentContainerStyle={styles.container}>
        <Heading style={styles.title}>Account Settings</Heading>
        <PasskeysCard title="My Passkeys" />
        <Text style={styles.hint}>
          Control plane settings are available to administrators only.
        </Text>
      </ScrollView>
    );
  }

  if (loading) {
    return (
      <View style={styles.containerCenter}>
        <ActivityIndicator color={colors.accent} size="large" aria-label="Loading settings" />
      </View>
    );
  }

  if (error && !config) {
    return (
      <View style={styles.containerCenter}>
        <ErrorWithRetry
          error={error}
          what="the control plane settings"
          onRetry={() => void refetch()}
        />
      </View>
    );
  }

  if (!config) return null;

  return (
    <ScrollView style={styles.scroll} contentContainerStyle={styles.container}>
      <Heading style={styles.title}>Control Plane Settings</Heading>

      <PasskeysCard title="My Passkeys" />

      {/* Identity */}
      <View style={styles.card}>
        <Heading level={2} style={styles.sectionTitle}>
          Identity
        </Heading>
        <DidRow
          label="Control Plane DID"
          did={config.controlDid}
          names={agentNames[config.controlDid ?? ""] ?? []}
        />
        <DidRow
          label="Mediator DID"
          did={config.mediatorDid}
          names={agentNames[config.mediatorDid ?? ""] ?? []}
        />
        <Row label="Control Plane URL" value={config.publicUrl ?? "Not configured"} />
        {config.didHostingUrl && <Row label="DID Hosting URL" value={config.didHostingUrl} />}
      </View>

      {generationsQuery.error != null && !generationsQuery.data && (
        <ErrorWithRetry
          error={generationsQuery.error}
          what="the key generations"
          onRetry={() => void generationsQuery.refetch()}
        />
      )}

      {/* Key generations. Only rendered when there is more than one — a
          service that has never rotated has nothing to say here, and a
          single-row panel would just be noise. */}
      {generations.length > 1 && (
        <View style={styles.card}>
          <Heading level={2} style={styles.sectionTitle}>
            Key Generations
          </Heading>
          <Text style={styles.explainer}>
            After a key rotation, peers holding a cached copy of this service&apos;s DID document
            keep encrypting to the old key. Superseded generations stay decryptable for a grace
            period so those messages still arrive.
          </Text>

          {generations.map((g) => (
            <View key={g.id} style={styles.generation}>
              <View style={styles.generationHeader}>
                <Text style={styles.generationTitle}>
                  Generation {g.id}
                  {g.current ? " · current" : ""}
                </Text>
                {!g.current && (
                  <Button
                    label="Retire now"
                    accessibilityLabel={`Retire generation ${g.id} now`}
                    variant="danger"
                    size="sm"
                    busy={retiring === g.id}
                    busyLabel="Retiring…"
                    onPress={() => retireGeneration(g)}
                  />
                )}
              </View>

              <Row label="Key agreement" value={g.keyAgreementKid} />
              {g.expiresAt !== null && (
                <View style={styles.row}>
                  <Text style={styles.label}>Honoured for</Text>
                  <Countdown expiresAt={g.expiresAt} style={styles.value} />
                </View>
              )}
            </View>
          ))}

          {identityError && (
            <Text role="alert" style={styles.errorText}>
              {identityError}
            </Text>
          )}
        </View>
      )}

      {/* Connectivity. `*Enabled` is what config turns on; the badge row
          below is what the control plane's DID document advertises to
          peers. They can disagree — the dashboard's Control Plane card
          spells out the consequences when they do. */}
      <View style={styles.card}>
        <Heading level={2} style={styles.sectionTitle}>
          Connectivity
        </Heading>
        {config.listenAddress ? <Row label="Listen Address" value={config.listenAddress} /> : null}
        <StatusRow label="DIDComm" enabled={config.didcommEnabled} />
        <StatusRow label="TSP" enabled={config.tspEnabled} />
        <View style={styles.row}>
          <Text style={styles.label}>Advertised services</Text>
          {config.advertisedServices ? (
            <ServiceBadges services={config.advertisedServices} emptyLabel="none in DID document" />
          ) : (
            <Text style={styles.advertisedUnknown}>DID not resolved</Text>
          )}
        </View>
      </View>

      {/* VTA */}
      {(config.vtaUrl || config.vtaDid) && (
        <View style={styles.card}>
          <Heading level={2} style={styles.sectionTitle}>
            VTA Integration
          </Heading>
          {config.vtaUrl && <Row label="VTA URL" value={config.vtaUrl} />}
          {config.vtaDid && (
            <DidRow label="VTA DID" did={config.vtaDid} names={agentNames[config.vtaDid] ?? []} />
          )}
        </View>
      )}

      {/* The sections below are optional in `server/config`: each renders
          only when the control plane states it. */}
      {config.registry && (
        <View style={styles.card}>
          <Heading level={2} style={styles.sectionTitle}>
            Service Registry
          </Heading>
          <Row
            label="Health Check Interval"
            value={interval(config.registry.healthCheckIntervalSecs)}
          />
          <Row
            label="Configured Instances"
            value={config.registry.configuredInstances.toString()}
          />
        </View>
      )}

      {config.sessions && (
        <View style={styles.card}>
          <Heading level={2} style={styles.sectionTitle}>
            Authentication
          </Heading>
          <Row
            label="Sign Out After Inactivity"
            value={interval(config.sessions.adminIdleTimeout)}
          />
          <Row label="Access Token Expiry" value={interval(config.sessions.accessTokenExpiry)} />
          <Row label="Refresh Token Expiry" value={interval(config.sessions.refreshTokenExpiry)} />
          <Row
            label="Passkey Enrollment TTL"
            value={interval(config.sessions.passkeyEnrollmentTtl)}
          />
        </View>
      )}

      {config.dataDir || config.logLevel || config.logFormat ? (
        <View style={styles.card}>
          <Heading level={2} style={styles.sectionTitle}>
            Storage & Logging
          </Heading>
          {config.dataDir ? <Row label="Data Directory" value={config.dataDir} /> : null}
          {config.logLevel ? <Row label="Log Level" value={config.logLevel} /> : null}
          {config.logFormat ? <Row label="Log Format" value={config.logFormat} /> : null}
        </View>
      ) : null}
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
  // The DID keeps `value`'s right alignment; the chips sit under it, right-
  // aligned to match, so the column edge stays straight down the card.
  didValue: {
    flex: 1,
    alignItems: "flex-end",
  },
  didValueNames: {
    marginTop: spacing.xs,
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
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
  },
});
