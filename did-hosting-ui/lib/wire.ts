/**
 * Wire → view model.
 *
 * The control plane answers every management call with the generated
 * response type of its Trust Task (`@openvtc/trust-tasks`): RFC 3339
 * timestamps, camelCase, host-specific members under the
 * `vnd.affinidi.webvh` extension namespace. The screens render epoch seconds
 * and flat records, so each reply is projected here, once, at the boundary.
 * Pure functions, so the projections are tested on their own.
 */

import type { DidRecord as WireDidRecord } from "@openvtc/trust-tasks/did-management/did/list/0.1/payload";
import type { Response as DidLogResponse } from "@openvtc/trust-tasks/did-management/did/log/0.1/payload";
import type { Response as ConfigResponse } from "@openvtc/trust-tasks/did-management/server/config/0.1/payload";
import type { Response as IdentityListResponse } from "@openvtc/trust-tasks/did-management/identity/list/0.1/payload";
import type { ServiceInstance as WireServiceInstance } from "@openvtc/trust-tasks/did-management/registry/list/0.1/payload";
import type { Response as StatsResponse } from "@openvtc/trust-tasks/did-management/stats/get/0.1/payload";
import type {
  Payload as TimeseriesPayload,
  Response as TimeseriesResponse,
} from "@openvtc/trust-tasks/did-management/stats/timeseries/0.1/payload";
import type { InviteSummary } from "@openvtc/trust-tasks/auth/passkey/enroll/invite/list/0.1/payload";
import type { AclEntry as WireAclEntry } from "@openvtc/trust-tasks/acl/list/0.1/payload";

import type {
  AclEntry,
  AgentNameEntry,
  ControlPlaneConfig,
  DidRecord,
  DomainBranding,
  DomainEntry,
  DomainQuota,
  DomainScope,
  IdentityGeneration,
  InviteListItem,
  LogEntryInfo,
  LogMetadata,
  PasskeyCredential,
  ServerStats,
  ServiceInstance,
  TimeRange,
  TimeSeriesPoint,
} from "./api";

/** The extension namespace this host's members travel under. */
export const WEBVH_EXT = "vnd.affinidi.webvh";

type Ext = Record<string, unknown> | undefined;

/** This host's extension object off a wire record, or `{}`. */
function webvhExt(ext: Ext): Record<string, any> {
  const v = ext?.[WEBVH_EXT];
  return v && typeof v === "object" ? (v as Record<string, any>) : {};
}

/** RFC 3339 → epoch seconds. `null` for absent or unreadable. */
export function epochSeconds(at: string | undefined | null): number | null {
  if (typeof at !== "string") return null;
  const ms = Date.parse(at);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/** As {@link epochSeconds}, for a member the schema requires. */
function requiredEpoch(at: string): number {
  return epochSeconds(at) ?? 0;
}

// ---------------------------------------------------------------------------
// DIDs
// ---------------------------------------------------------------------------

export function didRecordFromWire(r: WireDidRecord): DidRecord {
  const names = webvhExt(r.ext as Ext).agentNames;
  return {
    mnemonic: r.mnemonic,
    owner: r.owner,
    createdAt: requiredEpoch(r.createdAt),
    updatedAt: requiredEpoch(r.updatedAt),
    versionCount: r.versionCount,
    didId: r.didId ?? null,
    didUrl: r.didUrl ?? null,
    totalResolves: r.totalResolves ?? 0,
    disabled: r.disabled ?? false,
    ...(r.method ? { method: r.method } : {}),
    ...(r.domain ? { domain: r.domain } : {}),
    ...(Array.isArray(names) ? { agentNames: names as AgentNameEntry[] } : {}),
  };
}

export function logEntriesFromWire(resp: DidLogResponse): LogEntryInfo[] {
  return resp.entries.map((e) => ({
    versionId: e.versionId ?? null,
    versionTime: e.versionTime ?? null,
    state: (e.state as Record<string, any>) ?? null,
    parameters: (e.parameters as Record<string, any> | undefined) ?? null,
  }));
}

/**
 * Summarise a webvh log the way the detail screen shows it.
 *
 * did:webvh parameters are cumulative: each entry's `parameters` changes only
 * the members it names, so the effective value of each is the last one set.
 * `null` for an empty log.
 */
export function logMetadataFromEntries(
  entries: LogEntryInfo[],
): LogMetadata | null {
  if (entries.length === 0) return null;
  const effective: Record<string, any> = {};
  for (const e of entries) {
    if (e.parameters) Object.assign(effective, e.parameters);
  }
  const latest = entries[entries.length - 1]!;
  const witness =
    effective.witness && typeof effective.witness === "object"
      ? effective.witness
      : null;
  const witnessList: unknown[] = Array.isArray(witness?.witnesses)
    ? witness.witnesses
    : [];
  const watcherUrls: string[] = Array.isArray(effective.watchers)
    ? effective.watchers.filter(
        (w: unknown): w is string => typeof w === "string",
      )
    : [];
  return {
    logEntryCount: entries.length,
    latestVersionId: latest.versionId,
    latestVersionTime: latest.versionTime,
    method: typeof effective.method === "string" ? effective.method : null,
    portable: effective.portable === true,
    preRotation:
      Array.isArray(effective.nextKeyHashes) &&
      effective.nextKeyHashes.length > 0,
    witnesses: witnessList.length > 0,
    witnessCount: witnessList.length,
    witnessThreshold:
      typeof witness?.threshold === "number" ? witness.threshold : 0,
    watchers: watcherUrls.length > 0,
    watcherCount: watcherUrls.length,
    watcherUrls,
    deactivated: effective.deactivated === true,
    ttl: typeof effective.ttl === "number" ? effective.ttl : null,
  };
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

/** The host's `DomainBranding` / `DomainQuota` are its storage structs,
 *  serialised snake_case inside the extension. */
function brandingFromWire(b: any): DomainBranding | null {
  if (!b || typeof b !== "object") return null;
  return {
    logoUrl: b.logo_url ?? null,
    primaryColor: b.primary_color ?? null,
    displayName: b.display_name ?? null,
  };
}
function quotaFromWire(q: any): DomainQuota | null {
  if (!q || typeof q !== "object") return null;
  return { maxDids: q.max_dids ?? null, maxBytes: q.max_bytes ?? null };
}

/** The shared `DomainEntry` schema is open (`additionalProperties`), so the
 *  generated type is an index signature; the members read here are the ones
 *  `spec_domain_entry` writes. */
export function domainFromWire(wire: object): DomainEntry {
  const raw = wire as Record<string, unknown>;
  const host = webvhExt(raw.ext as Ext);
  return {
    name: String(raw.name),
    label: typeof raw.label === "string" ? raw.label : null,
    scheme: host.scheme === "http" ? "http" : "https",
    status: raw.status === "disabled" ? "disabled" : "active",
    createdAt: epochSeconds(raw.createdAt as string) ?? 0,
    defaultDomain: raw.defaultDomain === true,
    branding: brandingFromWire(host.branding),
    witnesses: Array.isArray(host.witnesses) ? host.witnesses : null,
    watchers: Array.isArray(host.watchers) ? host.watchers : null,
    quota: quotaFromWire(host.quota),
    wellKnownEnabled: host.wellKnownEnabled === true,
    disabledAt: epochSeconds(raw.disabledAt as string | undefined),
    purgeAt: epochSeconds(raw.purgeAt as string | undefined),
  };
}

// ---------------------------------------------------------------------------
// Fleet, stats, service
// ---------------------------------------------------------------------------

export function serviceInstanceFromWire(
  i: WireServiceInstance,
): ServiceInstance {
  return {
    instanceId: i.instanceId,
    did: i.did,
    serviceType: i.serviceType,
    label: i.label ?? null,
    url: i.publicUrl ?? null,
    status: i.status,
    lastHealthCheck: epochSeconds(i.lastHealthCheck),
    registeredAt: requiredEpoch(i.registeredAt),
    enabledMethods: i.enabledMethods ?? [],
    servedDomains: i.servedDomains,
    ...(i.advertisedServices
      ? { advertisedServices: i.advertisedServices }
      : {}),
    ...(i.servicesCheckedAt
      ? { servicesCheckedAt: epochSeconds(i.servicesCheckedAt) ?? undefined }
      : {}),
    ...(i.lastInbound
      ? {
          lastInboundTransport: i.lastInbound.transport,
          lastInboundAt: epochSeconds(i.lastInbound.at) ?? undefined,
        }
      : {}),
    ...(i.lastOutbound
      ? {
          lastOutboundTransport: i.lastOutbound.transport,
          lastOutboundAt: epochSeconds(i.lastOutbound.at) ?? undefined,
        }
      : {}),
  };
}

export function statsFromWire(s: StatsResponse): ServerStats {
  return {
    totalDids: s.totalDids ?? 0,
    totalResolves: s.totalResolves,
    totalUpdates: s.totalUpdates,
    lastResolvedAt: epochSeconds(s.lastResolvedAt),
    lastUpdatedAt: epochSeconds(s.lastUpdatedAt),
  };
}

const RANGE_TO_WIRE: Record<TimeRange, TimeseriesPayload["range"]> = {
  "1h": "lastHour",
  "24h": "lastDay",
  "7d": "lastWeek",
  "30d": "last30Days",
};

export function timeRangeToWire(range: TimeRange): TimeseriesPayload["range"] {
  return RANGE_TO_WIRE[range];
}

export function timeseriesFromWire(t: TimeseriesResponse): TimeSeriesPoint[] {
  return t.points.map((p) => ({
    timestamp: requiredEpoch(p.at),
    resolves: p.resolves,
    updates: p.updates,
  }));
}

export function configFromWire(c: ConfigResponse): ControlPlaneConfig {
  return {
    controlDid: c.serviceDid,
    softwareVersion: c.softwareVersion,
    deploymentMode: c.deploymentMode,
    publicUrl: c.publicUrl ?? null,
    didHostingUrl: c.didHostingUrl ?? null,
    mediatorDid: c.mediatorDid ?? null,
    didcommEnabled: c.transports.didcomm,
    tspEnabled: c.transports.tsp,
    ...(c.advertisedServices
      ? { advertisedServices: c.advertisedServices }
      : {}),
    enabledMethods: c.enabledMethods,
    agentNames: c.agentNames,
    listenAddress: c.listenAddress ?? null,
    vtaUrl: c.vta?.url ?? null,
    vtaDid: c.vta?.did ?? null,
    registry: c.registry
      ? {
          healthCheckIntervalSecs: c.registry.healthCheckIntervalSeconds,
          configuredInstances: c.registry.configuredInstances,
        }
      : null,
    sessions: c.sessions
      ? {
          accessTokenExpiry: c.sessions.accessTokenSeconds,
          refreshTokenExpiry: c.sessions.refreshTokenSeconds,
          adminIdleTimeout: c.sessions.adminIdleTimeoutSeconds,
          passkeyEnrollmentTtl: c.sessions.passkeyEnrollmentSeconds,
        }
      : null,
    dataDir: c.storage?.dataDir ?? null,
    logLevel: c.logging?.level ?? null,
    logFormat: c.logging?.format ?? null,
  };
}

export function identityFromWire(r: IdentityListResponse): {
  generations: IdentityGeneration[];
  rotationGraceSecs: number;
} {
  return {
    generations: r.generations.map((g) => ({
      id: g.generationId,
      did: g.did,
      current: g.current,
      signingKid: g.signingKeyId,
      keyAgreementKid: g.keyAgreementKeyId,
      mediatorDid: g.mediatorDid ?? null,
      didcomm: g.transports.didcomm,
      tsp: g.transports.tsp,
      createdAt: requiredEpoch(g.createdAt),
      retiredAt: epochSeconds(g.retiredAt),
      expiresAt: epochSeconds(g.expiresAt),
    })),
    rotationGraceSecs: r.rotationGraceSeconds,
  };
}

// ---------------------------------------------------------------------------
// Access
// ---------------------------------------------------------------------------

function role(r: string | undefined): "admin" | "owner" | "service" {
  return r === "admin" || r === "service" ? r : "owner";
}

export function inviteFromWire(i: InviteSummary): InviteListItem {
  return {
    inviteId: i.inviteId,
    did: i.subject,
    purpose: i.purpose,
    role: role(i.role),
    createdAt: requiredEpoch(i.createdAt),
    expiresAt: requiredEpoch(i.expiresAt),
    expired: i.expired,
  };
}

/** A wire credential summary — `auth/passkey/list`'s `RegisteredCredential`
 *  and `auth/passkey/admin-list`'s `ListedCredential` share this shape (the
 *  latter also carries an optional `signCount` this console doesn't show). */
interface WireCredentialSummary {
  credentialId: string;
  deviceLabel?: string;
  registeredAt: string;
  lastUsedAt?: string;
  transports?: string[];
}

export function passkeyCredentialFromWire(
  c: WireCredentialSummary,
): PasskeyCredential {
  return {
    credentialId: c.credentialId,
    deviceLabel: c.deviceLabel ?? null,
    registeredAt: requiredEpoch(c.registeredAt),
    lastUsedAt: epochSeconds(c.lastUsedAt),
    transports: c.transports ?? [],
  };
}

/** Project a spec-wire ACL entry into the `AclEntry` the screens render. The
 *  wire carries webvh fields under `ext["vnd.affinidi.webvh"]`. */
export function aclEntryFromWire(spec: WireAclEntry): AclEntry {
  const webvh = webvhExt(spec.ext as Ext);
  const quota: any = webvh.quota ?? {};
  return {
    did: spec.subject,
    role: role(spec.role),
    label: spec.label ?? null,
    created_at: epochSeconds(spec.createdAt) ?? 0,
    max_total_size:
      typeof quota.maxTotalSize === "number" ? quota.maxTotalSize : null,
    max_did_count:
      typeof quota.maxDidCount === "number" ? quota.maxDidCount : null,
    domains: (webvh.domains as DomainScope | undefined) ?? { kind: "all" },
  };
}
