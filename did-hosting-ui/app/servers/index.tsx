/**
 * Admin Servers view — registered service instances + per-server
 * domain assignment + admin "Purge now" controls.
 *
 * Each registered server is a card showing:
 * - DID + URL + health status badge
 * - enabled methods (badge per method)
 * - served domains (chips)
 * - "Assign domain" button → opens a picker over the configured
 *   domain list minus the already-served subset
 * - per-domain row: Unassign (schedules a pending purge with the
 *   server's `unassigned_purge_grace` window) and Purge now (admin
 *   trust task — bypasses the grace, deletes immediately).
 *
 * The screen reads the registry shape directly; the unassign /
 * purge calls are fire-and-forget DIDComm pushes. We surface the
 * 202 ack as a success toast; the actual ack from the server is
 * asynchronous and will reflect on a refresh.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ActivityIndicator,
  FlatList,
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { Link } from "expo-router";
import { useApi } from "../../components/ApiProvider";
import { useAuth } from "../../components/AuthProvider";
import { useDomains } from "../../components/DomainProvider";
import { ServiceBadges } from "../../components/ServiceBadges";
import { colors, fonts, radii, spacing } from "../../lib/theme";
import { showAlert, showConfirm } from "../../lib/alert";
import type { ServiceInstance } from "../../lib/api";

export default function ServersScreen() {
  const { isAuthenticated, role } = useAuth();
  const api = useApi();
  const { domains } = useDomains();

  const [instances, setInstances] = useState<ServiceInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [pickerFor, setPickerFor] = useState<ServiceInstance | null>(null);

  const refresh = useCallback(async () => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const list = await api.listRegistry();
      setInstances(list);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "failed to load registry");
    } finally {
      setLoading(false);
    }
  }, [api, isAuthenticated]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleAssign = useCallback(
    async (instance: ServiceInstance, domain: string) => {
      const key = `${instance.instanceId}:${domain}`;
      setBusy(key);
      setPickerFor(null);
      try {
        await api.assignDomainToServer(instance.instanceId, domain);
        showAlert(
          "Assignment queued",
          `${instance.label ?? instance.instanceId} will host ${domain} once the DIDComm push acks.`,
        );
        await refresh();
      } catch (e: unknown) {
        showAlert("Assign failed", e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(null);
      }
    },
    [api, refresh],
  );

  const handleUnassign = useCallback(
    (instance: ServiceInstance, domain: string) => {
      showConfirm(
        `Unassign ${domain} from this server?`,
        "DIDs hosted under this domain will be scheduled for purge after the " +
          "configured grace window (default 2h). Re-assigning within the grace cancels " +
          "the purge.",
        async () => {
          const key = `${instance.instanceId}:${domain}`;
          setBusy(key);
          try {
            await api.unassignDomainFromServer(instance.instanceId, domain);
            await refresh();
          } catch (e: unknown) {
            showAlert(
              "Unassign failed",
              e instanceof Error ? e.message : String(e),
            );
          } finally {
            setBusy(null);
          }
        },
      );
    },
    [api, refresh],
  );

  const handlePurge = useCallback(
    (instance: ServiceInstance, domain: string) => {
      showConfirm(
        `Purge ${domain} on this server NOW?`,
        "This bypasses the grace period and deletes every DID hosted under " +
          `${domain} on ${instance.label ?? instance.instanceId} immediately. ` +
          "The action is audit-logged with reason=admin-immediate and cannot be undone.",
        async () => {
          const key = `${instance.instanceId}:${domain}`;
          setBusy(key);
          try {
            await api.purgeDomainOnServer(instance.instanceId, domain);
            showAlert(
              "Purge dispatched",
              `Purge of ${domain} on ${instance.label ?? instance.instanceId} queued. The server's ack is asynchronous.`,
            );
          } catch (e: unknown) {
            showAlert(
              "Purge failed",
              e instanceof Error ? e.message : String(e),
            );
          } finally {
            setBusy(null);
          }
        },
      );
    },
    [api],
  );

  if (!isAuthenticated) {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>Please log in to manage servers.</Text>
        <Link href="/login" asChild>
          <Pressable style={styles.buttonPrimary}>
            <Text style={styles.buttonPrimaryText}>Login</Text>
          </Pressable>
        </Link>
      </View>
    );
  }
  if (role !== "admin") {
    return (
      <View style={styles.containerCenter}>
        <Text style={styles.hint}>
          Server administration is restricted to Admin accounts.
        </Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View style={{ flex: 1 }}>
          <Text style={styles.title}>Servers</Text>
          <Text style={styles.subtitle}>
            Registered hosting instances and the domains they serve.
            Assign / unassign drives the daemon's domain-assignment Trust
            Task; unassign queues a grace-window purge.
          </Text>
        </View>
        <Pressable
          accessibilityRole="button"
          style={styles.buttonSecondary}
          onPress={refresh}
        >
          <Text style={styles.buttonSecondaryText}>Refresh</Text>
        </Pressable>
      </View>

      {error && <Text style={styles.errorText}>{error}</Text>}

      {loading ? (
        <ActivityIndicator color={colors.accent} size="large" style={styles.spinner} />
      ) : instances.length === 0 ? (
        <Text style={styles.hint}>
          No servers registered yet. Servers register themselves on startup
          via DIDComm; check the daemon log if you expected to see one here.
        </Text>
      ) : (
        <FlatList
          data={instances}
          keyExtractor={(i) => i.instanceId}
          contentContainerStyle={{ gap: spacing.md }}
          renderItem={({ item }) => (
            <ServerCard
              instance={item}
              busyKey={busy}
              onAssign={() => setPickerFor(item)}
              onUnassign={(d) => handleUnassign(item, d)}
              onPurge={(d) => handlePurge(item, d)}
            />
          )}
        />
      )}

      <DomainPicker
        visible={pickerFor !== null}
        instance={pickerFor}
        availableDomains={
          pickerFor
            ? domains.filter((d) => !pickerFor.servedDomains.includes(d.name))
            : []
        }
        onPick={(domain) => pickerFor && handleAssign(pickerFor, domain)}
        onClose={() => setPickerFor(null)}
      />
    </View>
  );
}

function ServerCard({
  instance,
  busyKey,
  onAssign,
  onUnassign,
  onPurge,
}: {
  instance: ServiceInstance;
  busyKey: string | null;
  onAssign: () => void;
  onUnassign: (domain: string) => void;
  onPurge: (domain: string) => void;
}) {
  const did = useMemo(() => {
    const metaDid =
      typeof instance.metadata?.did === "string"
        ? instance.metadata.did
        : null;
    return metaDid ?? instance.instanceId.replace(/_/g, ":");
  }, [instance]);

  const healthColor =
    instance.status === "active"
      ? colors.success
      : instance.status === "degraded"
        ? colors.warning
        : colors.error;

  return (
    <View style={styles.card}>
      <View style={styles.cardHeader}>
        <View style={{ flex: 1 }}>
          <View style={styles.nameRow}>
            <Text style={styles.cardName}>
              {instance.label ?? "(unlabeled)"}
            </Text>
            <View
              style={[styles.statusBadge, { backgroundColor: colors.bgTertiary }]}
            >
              <View
                style={[
                  styles.healthDot,
                  { backgroundColor: healthColor },
                ]}
              />
              <Text style={styles.statusBadgeText}>{instance.status}</Text>
            </View>
            <View style={styles.statusBadge}>
              <Text style={styles.statusBadgeText}>
                {instance.serviceType}
              </Text>
            </View>
          </View>
          <Text style={styles.cardSubline} numberOfLines={1}>
            {did}
          </Text>
          <Text style={styles.cardUrl} numberOfLines={1}>
            {instance.url}
          </Text>
          {/* Transports/services this server's DID document advertises —
              resolved and cached at register + health check. Distinct from
              `enabledMethods` below, which is what its binary supports. */}
          <View style={styles.servicesRow}>
            <Text style={styles.servicesLabel}>Advertises</Text>
            {instance.advertisedServices ? (
              <ServiceBadges
                services={instance.advertisedServices}
                emptyLabel="no services in DID document"
              />
            ) : (
              <Text style={styles.servicesUnknown}>
                {instance.metadata?.did
                  ? "DID not resolved yet"
                  : "no DID recorded"}
              </Text>
            )}
          </View>
          <View style={styles.metaRow}>
            {instance.enabledMethods.map((m) => (
              <View key={m} style={styles.methodBadge}>
                <Text style={styles.methodBadgeText}>did:{m}</Text>
              </View>
            ))}
            <Text style={styles.metaText}>
              proto {instance.protocolVersion}
            </Text>
          </View>
        </View>
        <Pressable
          accessibilityRole="button"
          onPress={onAssign}
          style={styles.buttonPrimary}
        >
          <Text style={styles.buttonPrimaryText}>+ Assign domain</Text>
        </Pressable>
      </View>

      <View style={styles.divider} />

      {instance.servedDomains.length === 0 ? (
        <Text style={styles.emptyDomains}>
          No domains assigned yet. Use "+ Assign domain" to begin hosting.
        </Text>
      ) : (
        <View style={{ gap: spacing.sm }}>
          {instance.servedDomains.map((d) => {
            const key = `${instance.instanceId}:${d}`;
            const isBusy = busyKey === key;
            return (
              <View key={d} style={styles.domainRow}>
                <Text style={styles.domainRowName}>{d}</Text>
                <View style={styles.domainRowActions}>
                  <Pressable
                    accessibilityRole="button"
                    onPress={() => onUnassign(d)}
                    disabled={isBusy}
                    style={[
                      styles.buttonSecondary,
                      isBusy && styles.buttonDisabled,
                    ]}
                  >
                    <Text style={styles.buttonSecondaryText}>
                      {isBusy ? "…" : "Unassign"}
                    </Text>
                  </Pressable>
                  <Pressable
                    accessibilityRole="button"
                    onPress={() => onPurge(d)}
                    disabled={isBusy}
                    style={[
                      styles.buttonDanger,
                      isBusy && styles.buttonDisabled,
                    ]}
                  >
                    <Text style={styles.buttonDangerText}>
                      {isBusy ? "…" : "Purge now"}
                    </Text>
                  </Pressable>
                </View>
              </View>
            );
          })}
        </View>
      )}
    </View>
  );
}

function DomainPicker({
  visible,
  instance,
  availableDomains,
  onPick,
  onClose,
}: {
  visible: boolean;
  instance: ServiceInstance | null;
  availableDomains: ReturnType<typeof useDomains>["domains"];
  onPick: (domain: string) => void;
  onClose: () => void;
}) {
  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={onClose}
    >
      <Pressable style={styles.overlay} onPress={onClose}>
        <Pressable
          style={styles.popover}
          onPress={(e) => e.stopPropagation()}
          accessibilityLabel="Pick a domain to assign"
        >
          <Text style={styles.popoverTitle}>
            Assign domain to {instance?.label ?? "this server"}
          </Text>
          {availableDomains.length === 0 ? (
            <Text style={styles.hint}>
              No unassigned domains available. Create a new one on the
              Domains page, or unassign it from another server first.
            </Text>
          ) : (
            <ScrollView style={{ marginTop: spacing.sm }}>
              {availableDomains.map((d) => (
                <Pressable
                  key={d.name}
                  accessibilityRole="button"
                  onPress={() => onPick(d.name)}
                  style={({ pressed }) => [
                    styles.pickerOption,
                    pressed && styles.pickerOptionPressed,
                    d.status === "disabled" && styles.buttonDisabled,
                  ]}
                  disabled={d.status === "disabled"}
                >
                  <Text style={styles.pickerOptionName}>{d.name}</Text>
                  {!!d.label && (
                    <Text style={styles.pickerOptionLabel}>{d.label}</Text>
                  )}
                  {d.status === "disabled" && (
                    <Text style={styles.pickerOptionDisabledHint}>
                      Disabled — re-enable on Domains page first
                    </Text>
                  )}
                </Pressable>
              ))}
            </ScrollView>
          )}
        </Pressable>
      </Pressable>
    </Modal>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    gap: spacing.lg,
  },
  containerCenter: {
    flex: 1,
    padding: spacing.xl,
    backgroundColor: colors.bgPrimary,
    alignItems: "center",
    justifyContent: "center",
  },
  spinner: { marginTop: spacing.xxl },
  header: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: spacing.md,
    flexWrap: "wrap",
  },
  title: {
    fontSize: 24,
    fontFamily: fonts.bold,
    color: colors.textPrimary,
  },
  subtitle: {
    marginTop: 4,
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    maxWidth: 640,
  },
  hint: {
    fontSize: 14,
    fontFamily: fonts.regular,
    color: colors.textSecondary,
    textAlign: "center",
    marginTop: spacing.xl,
    paddingHorizontal: spacing.md,
  },
  errorText: {
    fontFamily: fonts.medium,
    color: colors.error,
  },
  card: {
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    gap: spacing.md,
  },
  cardHeader: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: spacing.md,
  },
  nameRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    flexWrap: "wrap",
  },
  cardName: {
    fontFamily: fonts.semibold,
    fontSize: 16,
    color: colors.textPrimary,
  },
  cardSubline: {
    marginTop: 4,
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.textTertiary,
  },
  cardUrl: {
    marginTop: 2,
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.textSecondary,
  },
  servicesRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    marginTop: spacing.sm,
    flexWrap: "wrap",
  },
  servicesLabel: {
    fontFamily: fonts.medium,
    fontSize: 11,
    color: colors.textTertiary,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },
  servicesUnknown: {
    fontFamily: fonts.regular,
    fontSize: 11,
    color: colors.textTertiary,
    fontStyle: "italic",
  },
  metaRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.sm,
    marginTop: spacing.sm,
    flexWrap: "wrap",
  },
  metaText: {
    fontFamily: fonts.regular,
    fontSize: 11,
    color: colors.textTertiary,
  },
  methodBadge: {
    backgroundColor: colors.tealMuted,
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
    borderRadius: radii.sm,
  },
  methodBadgeText: {
    fontFamily: fonts.semibold,
    fontSize: 10,
    color: colors.teal,
    letterSpacing: 0.4,
  },
  statusBadge: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
    borderRadius: radii.sm,
    backgroundColor: colors.bgTertiary,
  },
  statusBadgeText: {
    fontFamily: fonts.semibold,
    fontSize: 10,
    color: colors.textSecondary,
    letterSpacing: 0.4,
    textTransform: "capitalize",
  },
  healthDot: { width: 6, height: 6, borderRadius: 3 },
  divider: {
    height: 1,
    backgroundColor: colors.border,
    marginVertical: spacing.xs,
  },
  emptyDomains: {
    fontSize: 13,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    fontStyle: "italic",
  },
  domainRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    padding: spacing.sm,
    borderRadius: radii.sm,
    backgroundColor: colors.bgPrimary,
  },
  domainRowName: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 13,
    color: colors.textPrimary,
  },
  domainRowActions: {
    flexDirection: "row",
    gap: spacing.sm,
  },
  buttonPrimary: {
    backgroundColor: colors.accent,
    borderRadius: radii.md,
    paddingVertical: 8,
    paddingHorizontal: spacing.md,
    alignItems: "center",
  },
  buttonPrimaryText: {
    color: colors.textOnAccent,
    fontFamily: fonts.semibold,
    fontSize: 13,
  },
  buttonSecondary: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
  },
  buttonSecondaryText: {
    color: colors.textSecondary,
    fontFamily: fonts.semibold,
    fontSize: 12,
  },
  buttonDanger: {
    backgroundColor: "transparent",
    borderRadius: radii.md,
    borderWidth: 1,
    borderColor: colors.error,
    paddingVertical: 6,
    paddingHorizontal: spacing.md,
  },
  buttonDangerText: {
    color: colors.error,
    fontFamily: fonts.semibold,
    fontSize: 12,
  },
  buttonDisabled: { opacity: 0.5 },
  overlay: {
    flex: 1,
    backgroundColor: colors.overlay,
    alignItems: "center",
    justifyContent: "center",
    padding: spacing.lg,
  },
  popover: {
    width: "100%",
    maxWidth: 480,
    maxHeight: "80%",
    backgroundColor: colors.bgSecondary,
    borderRadius: radii.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
  },
  popoverTitle: {
    fontFamily: fonts.semibold,
    fontSize: 14,
    color: colors.textPrimary,
  },
  pickerOption: {
    paddingVertical: spacing.md,
    paddingHorizontal: spacing.md,
    borderRadius: radii.md,
    marginBottom: spacing.xs,
  },
  pickerOptionPressed: { backgroundColor: colors.bgTertiary },
  pickerOptionName: {
    fontFamily: fonts.mono,
    fontSize: 14,
    color: colors.textPrimary,
  },
  pickerOptionLabel: {
    fontFamily: fonts.regular,
    fontSize: 12,
    color: colors.textSecondary,
    marginTop: 2,
  },
  pickerOptionDisabledHint: {
    fontFamily: fonts.regular,
    fontSize: 11,
    color: colors.error,
    marginTop: 2,
  },
});
