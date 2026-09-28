/**
 * The console's client for its control plane.
 *
 * Every management call is a signed Trust Task through `POST /api/trust-tasks`
 * (see `trust-task.ts` for the binding and how replies are checked). The
 * request and response shapes are the generated types in
 * `@openvtc/trust-tasks`; `wire.ts` projects each reply into the view models
 * below, which are what the screens render.
 *
 * Two things stay plain HTTP: the unauthenticated `/api/health` liveness
 * probe and the REST token refresh in `session.ts`. Passkey enrolment and
 * login are Trust Tasks too; only the browser's WebAuthn ceremony is not, and
 * its data rides inside their payloads.
 */

import type * as DidList from "@openvtc/trust-tasks/did-management/did/list/0.1/payload";
import type * as DidInfo from "@openvtc/trust-tasks/did-management/did/info/0.1/payload";
import type * as DidLog from "@openvtc/trust-tasks/did-management/did/log/0.1/payload";
import type * as DidCheckName from "@openvtc/trust-tasks/did-management/did/check-name/0.1/payload";
import type * as DidRegister from "@openvtc/trust-tasks/did-management/did/register/0.1/payload";
import type * as DidDelete from "@openvtc/trust-tasks/did-management/did/delete/0.1/payload";
import type * as DidChangeOwner from "@openvtc/trust-tasks/did-management/did/change-owner/0.1/payload";
import type * as DidRollback from "@openvtc/trust-tasks/did-management/did/rollback/0.1/payload";
import type * as WitnessPublish from "@openvtc/trust-tasks/webvh/witness/publish/0.1/payload";
import type * as AgentNameCheck from "@openvtc/trust-tasks/did-management/agent-name/check/0.1/payload";
import type * as AgentNameResolve from "@openvtc/trust-tasks/did-management/agent-name/resolve/0.1/payload";
import type * as DomainList from "@openvtc/trust-tasks/did-management/domain/list/0.1/payload";
import type * as MeDomains from "@openvtc/trust-tasks/did-management/me/domains/0.1/payload";
import type * as DomainCreate from "@openvtc/trust-tasks/did-management/domain/create/0.1/payload";
import type * as DomainSetState from "@openvtc/trust-tasks/did-management/domain/set-state/0.1/payload";
import type * as DomainSetDefault from "@openvtc/trust-tasks/did-management/domain/set-default/0.1/payload";
import type * as DomainPurge from "@openvtc/trust-tasks/did-management/domain/purge/0.1/payload";
import type * as DomainAssign from "@openvtc/trust-tasks/did-management/domain/assign/0.1/payload";
import type * as DomainUnassign from "@openvtc/trust-tasks/did-management/domain/unassign/0.1/payload";
import type * as RegistryList from "@openvtc/trust-tasks/did-management/registry/list/0.1/payload";
import type * as RegistryPurgeDomain from "@openvtc/trust-tasks/did-management/registry/purge-domain/0.1/payload";
import type * as StatsGet from "@openvtc/trust-tasks/did-management/stats/get/0.1/payload";
import type * as StatsTimeseries from "@openvtc/trust-tasks/did-management/stats/timeseries/0.1/payload";
import type * as ServerConfig from "@openvtc/trust-tasks/did-management/server/config/0.1/payload";
import type * as IdentityList from "@openvtc/trust-tasks/did-management/identity/list/0.1/payload";
import type * as IdentityRetire from "@openvtc/trust-tasks/did-management/identity/retire/0.1/payload";
import type * as LoginStart from "@openvtc/trust-tasks/auth/passkey/login/start/0.2/payload";
import type * as LoginFinish from "@openvtc/trust-tasks/auth/passkey/login/finish/0.2/payload";
import type * as Invite from "@openvtc/trust-tasks/auth/passkey/enroll/invite/0.2/payload";
import type * as RedeemStart from "@openvtc/trust-tasks/auth/passkey/enroll/redeem/start/0.1/payload";
import type * as RedeemFinish from "@openvtc/trust-tasks/auth/passkey/enroll/redeem/finish/0.1/payload";
import type * as InviteList from "@openvtc/trust-tasks/auth/passkey/enroll/invite/list/0.1/payload";
import type * as InviteUpdate from "@openvtc/trust-tasks/auth/passkey/enroll/invite/update/0.1/payload";
import type * as InviteRevoke from "@openvtc/trust-tasks/auth/passkey/enroll/invite/revoke/0.1/payload";
import type * as AclList from "@openvtc/trust-tasks/acl/list/0.1/payload";
import type * as AclShow from "@openvtc/trust-tasks/acl/show/0.1/payload";
import type * as AclGrant from "@openvtc/trust-tasks/acl/grant/0.1/payload";
import type * as AclRevoke from "@openvtc/trust-tasks/acl/revoke/0.1/payload";
import type * as AclChangeRole from "@openvtc/trust-tasks/acl/change-role/0.1/payload";
import type { Response as ServerInfo } from "@openvtc/trust-tasks/did-management/server/info/0.1/payload";
import type * as RevokeSession from "@openvtc/trust-tasks/auth/revoke-session/0.2/payload";

import { ApiError, request } from "./http";
import {
  clearToken,
  getAuthMethod,
  getRefreshToken,
  getSessionId,
  getToken,
  setRefreshToken,
  setToken,
} from "./session";
import { hasSessionKeypair, restoreSessionKeypair } from "./session-key";
import { getServiceInfo, isRejection, trustTask } from "./trust-task";
import { getApiBase } from "./api-base";
import {
  aclEntryFromWire,
  configFromWire,
  didRecordFromWire,
  domainFromWire,
  identityFromWire,
  inviteFromWire,
  logEntriesFromWire,
  logMetadataFromEntries,
  serviceInstanceFromWire,
  statsFromWire,
  timeRangeToWire,
  timeseriesFromWire,
  WEBVH_EXT,
} from "./wire";

export { ApiError } from "./http";
export * from "./session";
export {
  TrustTaskRejection,
  checkReply,
  isRejection,
  resetServiceInfo,
  retryDelayMs,
} from "./trust-task";
export type { ServerInfo };

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string;
  version: string;
}

/** DID hosting method tag carried on every DidRecord. */
export type DidMethod = "webvh" | "web" | "webs" | "webplus" | string;

export interface DidRecord {
  mnemonic: string;
  owner: string;
  createdAt: number;
  updatedAt: number;
  versionCount: number;
  didId: string | null;
  /** Where the slot's log is served. */
  didUrl: string | null;
  totalResolves: number;
  /** Suspended with `did/set-state`: resolves nowhere until resumed. */
  disabled: boolean;
  method?: DidMethod;
  domain?: string;
  /** The slot's agent names from the authoritative registry, including parked
   *  ones — filter with `servedNames` before showing them as resolvable.
   *  Absent when the DID has none. */
  agentNames?: AgentNameEntry[];
}

export type DomainStatus = "active" | "disabled";
export type DomainUrlScheme = "https" | "http";

export interface DomainBranding {
  logoUrl?: string | null;
  primaryColor?: string | null;
  displayName?: string | null;
}

export interface DomainQuota {
  maxDids?: number | null;
  maxBytes?: number | null;
}

export interface DomainEntry {
  name: string;
  label: string | null;
  scheme: DomainUrlScheme;
  status: DomainStatus;
  createdAt: number;
  defaultDomain: boolean;
  branding: DomainBranding | null;
  witnesses: string[] | null;
  watchers: string[] | null;
  quota: DomainQuota | null;
  wellKnownEnabled: boolean;
  /** Unix seconds when disable was called. Null while Active. The domain and
   *  every hosted DID is permanently removed at `purgeAt` unless the operator
   *  re-enables before then. */
  disabledAt: number | null;
  /** Unix seconds at which the disabled domain becomes eligible for the
   *  background purge sweep. Null while Active. */
  purgeAt: number | null;
}

export interface DomainListResponse {
  domains: DomainEntry[];
  /** Currently-elected default; may be null on a fresh install. */
  default: string | null;
}

/** Per-ACL `DomainScope`. Tagged with `kind`. */
export type DomainScope =
  | { kind: "all" }
  | { kind: "allowed"; domains: string[] }
  | { kind: "allowed_with_default"; domains: string[]; default: string };

/** A transport observed carrying real traffic. */
export type ObservedTransport = "tsp" | "didcomm" | "https";

/** One registered service instance (`registry/list`). */
export interface ServiceInstance {
  instanceId: string;
  did: string;
  serviceType: "server" | "witness" | "watcher";
  label: string | null;
  url: string | null;
  status: "active" | "degraded" | "unreachable";
  lastHealthCheck: number | null;
  registeredAt: number;
  enabledMethods: string[];
  servedDomains: string[];
  /** `service[].type` values resolved from this instance's DID document.
   *  Distinct from `enabledMethods`, which is what its binary supports. */
  advertisedServices?: string[];
  /** Epoch seconds of the last successful resolve of `advertisedServices`. */
  servicesCheckedAt?: number;
  /** The transport that **actually carried** the last message in each
   *  direction. Distinct from `advertisedServices`, which is only what the
   *  peer says it can speak. */
  lastInboundTransport?: ObservedTransport;
  lastInboundAt?: number;
  lastOutboundTransport?: ObservedTransport;
  lastOutboundAt?: number;
}

export interface LogMetadata {
  logEntryCount: number;
  latestVersionId: string | null;
  latestVersionTime: string | null;
  method: string | null;
  portable: boolean;
  preRotation: boolean;
  witnesses: boolean;
  witnessCount: number;
  witnessThreshold: number;
  watchers: boolean;
  watcherCount: number;
  watcherUrls: string[];
  deactivated: boolean;
  ttl: number | null;
}

/** A slot with its log summarised. */
export interface DidDetailResponse extends DidRecord {
  log: LogMetadata | null;
}

export interface LogEntryInfo {
  versionId: string | null;
  versionTime: string | null;
  state: Record<string, any> | null;
  parameters: Record<string, any> | null;
}

export interface CreateDidResponse {
  mnemonic: string;
  didUrl: string | null;
}

export interface CheckNameResponse {
  available: boolean;
}

/** One agent name in a DID's authoritative registry. A parked name
 *  (`enabled: false`) is absent from the document's `alsoKnownAs`, so this is
 *  the only way to surface it. */
export interface AgentNameEntry {
  name: string;
  enabled: boolean;
  createdAt: number;
}

/** DID -> served agent names (bare local parts). DIDs with none are omitted,
 *  so a missing key and an empty array mean the same thing. */
export interface AgentNameResolveResponse {
  names: Record<string, string[]>;
}

/** Availability of an agent name (`/@alice`) on a hosting domain. */
export interface AgentNameAvailability {
  name: string;
  domain: string;
  /** Free to claim: neither reserved nor already bound on this domain. */
  available: boolean;
  /** On the host's reserved list (`@admin`, `@support`, …) — unavailable but
   *  a well-formed name. */
  reserved: boolean;
}

export interface AclEntry {
  did: string;
  role: "admin" | "owner" | "service";
  label: string | null;
  created_at: number;
  max_total_size: number | null;
  max_did_count: number | null;
  domains?: DomainScope;
}

export interface AclListResponse {
  entries: AclEntry[];
}

export interface DidStats {
  totalResolves: number;
  totalUpdates: number;
  lastResolvedAt: number | null;
  lastUpdatedAt: number | null;
}

export interface ServerStats extends DidStats {
  totalDids: number;
}

export interface TimeSeriesPoint {
  timestamp: number;
  resolves: number;
  updates: number;
}

export type TimeRange = "1h" | "24h" | "7d" | "30d";

/** The dashboard's view of the deployment: the control plane itself, the
 *  registered fleet, and the totals. Composed from `server/config`,
 *  `registry/list` and `stats/get`. */
export interface ServiceOverview {
  control: ControlInfo;
  services: ServiceInfo[];
  aggregate: AggregateStats;
}

export interface ControlInfo {
  version: string;
  serverDid: string | null;
  publicUrl: string | null;
  /** Transport turned on in config. */
  didcommEnabled: boolean;
  /** Transport turned on in config. */
  tspEnabled: boolean;
  /** What the control plane's own DID document advertises to peers. May
   *  disagree with the `*Enabled` flags above. Absent when the DID would not
   *  resolve, in which case the comparison can't be made. */
  advertisedServices?: string[];
  /** DID methods compiled into this control-plane binary. Empty means every
   *  DID op fails; the dashboard warns loudly. */
  enabledMethods: string[];
}

export type ServiceInfo = ServiceInstance;

export interface AggregateStats {
  totalServices: number;
  activeServices: number;
  degradedServices: number;
  unreachableServices: number;
  totalDids: number;
  totalResolves: number;
  totalUpdates: number;
}

export interface LoginStartResponse {
  authId: string;
  /** WebAuthn request options, in the shape `navigator.credentials.get` takes
   *  under `publicKey` (base64url members still encoded). */
  options: LoginStart.Response["options"];
}

export interface LoginTokens {
  accessToken: string;
  refreshToken: string | null;
}

/** What a credential enrolled by invite may do: sign in (`session`), or only
 *  confirm a step-up for one operation (`stepUp`), never sign in. */
export type InvitePurpose = "session" | "stepUp";

/** A freshly issued invite. `inviteUrl` and `claimCode` are shown once, here,
 *  and are to be sent over two different channels; the control plane keeps
 *  only their hashes and never returns either again. */
export interface CreateInviteResponse {
  inviteUrl: string;
  claimCode: string;
  subject: string;
  purpose: InvitePurpose;
  expiresAt: number;
}

/** The registration an invite authorises, before the passkey is created. */
export type RedeemStartResponse = RedeemStart.Response;

/** The credential an invite bound. */
export type RedeemFinishResponse = RedeemFinish.Response;

/** A pending invite as an administrator sees it later: addressed by
 *  `inviteId`. The token is shown once, when the invite is created, and is
 *  never sent back. */
export interface InviteListItem {
  inviteId: string;
  did: string;
  purpose: InvitePurpose;
  role: "admin" | "owner" | "service";
  createdAt: number;
  expiresAt: number;
  expired: boolean;
}

export interface InviteListResponse {
  invites: InviteListItem[];
}

/** `server/config`: what an operator needs to see. No secrets, by rule. */
export interface ControlPlaneConfig {
  controlDid: string;
  softwareVersion: string;
  deploymentMode: string;
  publicUrl: string | null;
  didHostingUrl: string | null;
  mediatorDid: string | null;
  didcommEnabled: boolean;
  tspEnabled: boolean;
  /** `service[].type` from the control plane's own DID document. */
  advertisedServices?: string[];
  enabledMethods: string[];
  agentNames: boolean;
  listenAddress: string | null;
  vtaUrl: string | null;
  vtaDid: string | null;
  registry: { healthCheckIntervalSecs: number; configuredInstances: number } | null;
  sessions: {
    accessTokenExpiry: number;
    refreshTokenExpiry: number;
    adminIdleTimeout: number;
    passkeyEnrollmentTtl: number;
  } | null;
  dataDir: string | null;
  logLevel: string | null;
  logFormat: string | null;
}

/**
 * One version of this service's own DID identity.
 *
 * After a key rotation, peers holding a cached DID document keep encrypting to
 * the *old* key-agreement key. A superseded generation therefore stays
 * decryptable until `expiresAt`, so those messages still arrive.
 */
export interface IdentityGeneration {
  id: number;
  did: string;
  /** The generation the DID document currently advertises. Cannot be retired. */
  current: boolean;
  signingKid: string;
  keyAgreementKid: string;
  mediatorDid: string | null;
  didcomm: boolean;
  tsp: boolean;
  createdAt: number;
  /** When it stopped being current. `null` on the current generation. */
  retiredAt: number | null;
  /** When it stops being honoured. `null` on the current generation. */
  expiresAt: number | null;
}

export interface IdentityGenerationsResponse {
  generations: IdentityGeneration[];
  /** How long a generation retired from now would keep being honoured. */
  rotationGraceSecs: number;
}

// ---------------------------------------------------------------------------
// Task type URIs
//
// Each is typed as its generated `TYPE_URI`, so a typo or a version the
// package does not know fails the typecheck. Only the types are imported —
// the generated modules carry their schemas as values, which the bundle does
// not need.
// ---------------------------------------------------------------------------

const TT = "https://trusttasks.org/spec/";
const DM = `${TT}did-management/` as const;

const T = {
  didList: `${DM}did/list/0.1` as const satisfies typeof DidList.TYPE_URI,
  didInfo: `${DM}did/info/0.1` as const satisfies typeof DidInfo.TYPE_URI,
  didLog: `${DM}did/log/0.1` as const satisfies typeof DidLog.TYPE_URI,
  didCheckName: `${DM}did/check-name/0.1` as const satisfies typeof DidCheckName.TYPE_URI,
  didRegister: `${DM}did/register/0.1` as const satisfies typeof DidRegister.TYPE_URI,
  didDelete: `${DM}did/delete/0.1` as const satisfies typeof DidDelete.TYPE_URI,
  didChangeOwner: `${DM}did/change-owner/0.1` as const satisfies typeof DidChangeOwner.TYPE_URI,
  didRollback: `${DM}did/rollback/0.1` as const satisfies typeof DidRollback.TYPE_URI,
  witnessPublish: `${TT}webvh/witness/publish/0.1` as const satisfies typeof WitnessPublish.TYPE_URI,
  agentNameCheck: `${DM}agent-name/check/0.1` as const satisfies typeof AgentNameCheck.TYPE_URI,
  agentNameResolve: `${DM}agent-name/resolve/0.1` as const satisfies typeof AgentNameResolve.TYPE_URI,
  domainList: `${DM}domain/list/0.1` as const satisfies typeof DomainList.TYPE_URI,
  meDomains: `${DM}me/domains/0.1` as const satisfies typeof MeDomains.TYPE_URI,
  domainCreate: `${DM}domain/create/0.1` as const satisfies typeof DomainCreate.TYPE_URI,
  domainSetState: `${DM}domain/set-state/0.1` as const satisfies typeof DomainSetState.TYPE_URI,
  domainSetDefault: `${DM}domain/set-default/0.1` as const satisfies typeof DomainSetDefault.TYPE_URI,
  domainPurge: `${DM}domain/purge/0.1` as const satisfies typeof DomainPurge.TYPE_URI,
  domainAssign: `${DM}domain/assign/0.1` as const satisfies typeof DomainAssign.TYPE_URI,
  domainUnassign: `${DM}domain/unassign/0.1` as const satisfies typeof DomainUnassign.TYPE_URI,
  registryList: `${DM}registry/list/0.1` as const satisfies typeof RegistryList.TYPE_URI,
  registryPurgeDomain: `${DM}registry/purge-domain/0.1` as const satisfies typeof RegistryPurgeDomain.TYPE_URI,
  statsGet: `${DM}stats/get/0.1` as const satisfies typeof StatsGet.TYPE_URI,
  statsTimeseries: `${DM}stats/timeseries/0.1` as const satisfies typeof StatsTimeseries.TYPE_URI,
  serverConfig: `${DM}server/config/0.1` as const satisfies typeof ServerConfig.TYPE_URI,
  identityList: `${DM}identity/list/0.1` as const satisfies typeof IdentityList.TYPE_URI,
  identityRetire: `${DM}identity/retire/0.1` as const satisfies typeof IdentityRetire.TYPE_URI,
  loginStart: `${TT}auth/passkey/login/start/0.2` as const satisfies typeof LoginStart.TYPE_URI,
  loginFinish: `${TT}auth/passkey/login/finish/0.2` as const satisfies typeof LoginFinish.TYPE_URI,
  invite: `${TT}auth/passkey/enroll/invite/0.2` as const satisfies typeof Invite.TYPE_URI,
  redeemStart: `${TT}auth/passkey/enroll/redeem/start/0.1` as const satisfies typeof RedeemStart.TYPE_URI,
  redeemFinish: `${TT}auth/passkey/enroll/redeem/finish/0.1` as const satisfies typeof RedeemFinish.TYPE_URI,
  inviteList: `${TT}auth/passkey/enroll/invite/list/0.1` as const satisfies typeof InviteList.TYPE_URI,
  inviteUpdate: `${TT}auth/passkey/enroll/invite/update/0.1` as const satisfies typeof InviteUpdate.TYPE_URI,
  inviteRevoke: `${TT}auth/passkey/enroll/invite/revoke/0.1` as const satisfies typeof InviteRevoke.TYPE_URI,
  aclList: `${TT}acl/list/0.1` as const satisfies typeof AclList.TYPE_URI,
  revokeSession: `${TT}auth/revoke-session/0.2` as const satisfies typeof RevokeSession.TYPE_URI,
  aclShow: `${TT}acl/show/0.1` as const satisfies typeof AclShow.TYPE_URI,
  aclGrant: `${TT}acl/grant/0.1` as const satisfies typeof AclGrant.TYPE_URI,
  aclRevoke: `${TT}acl/revoke/0.1` as const satisfies typeof AclRevoke.TYPE_URI,
  aclChangeRole: `${TT}acl/change-role/0.1` as const satisfies typeof AclChangeRole.TYPE_URI,
} as const;

/** Largest page `did/list` answers. */
const DID_LIST_PAGE = 1000;

/** The control plane's `did/log` for `mnemonic`. */
function didLog(mnemonic: string, raw: boolean): Promise<DidLog.Response> {
  return trustTask<DidLog.Payload, DidLog.Response>(T.didLog, {
    mnemonic,
    ...(raw ? { raw: true } : {}),
  });
}

/** The webvh extension object an ACL grant carries. */
function webvhAclExt(
  domains: DomainScope,
  maxTotalSize: number | null | undefined,
  maxDidCount: number | null | undefined,
): Record<string, unknown> {
  const ext: Record<string, unknown> = { domains };
  const quota: Record<string, number> = {};
  if (typeof maxTotalSize === "number") quota.maxTotalSize = maxTotalSize;
  if (typeof maxDidCount === "number") quota.maxDidCount = maxDidCount;
  if (Object.keys(quota).length > 0) ext.quota = quota;
  return { [WEBVH_EXT]: ext };
}

// ---------------------------------------------------------------------------
// ACL subject resolution — an agent name typed where an ACL takes a DID
// ---------------------------------------------------------------------------
//
// `acl/grant` stores whatever `subject` it is given verbatim — the control
// plane resolves nothing (unlike the removed REST `POST /api/acl`, which
// resolved a name to a DID server-side via `resolve_did_or_agent_name`
// before it ever reached storage). A subject typed as a name the console
// doesn't resolve first would silently create an entry keyed on a string
// nothing can ever authenticate as.

/** Cheap syntactic test — the `/@` marker — mirroring
 *  `agent_names::AgentName::looks_like_agent_name` (Rust) used server-side
 *  for the same purpose. No network access; just decides whether `input`
 *  is an agent name shape before doing any resolution work. */
export function looksLikeAgentName(input: string): boolean {
  return input.includes("/@");
}

/** Split an agent name (`example.com/@alice`, with or without a leading
 *  `https://`, and tolerant of trailing context path segments or a
 *  trailing slash) into its hosting domain and bare local name. `null`
 *  when the `/@` marker is present but the surrounding shape isn't one
 *  this parser understands — an empty domain, the community name
 *  (`example.com/@`, which no ACL role can be granted to), or a second
 *  `/@` marker. Domain is lower-cased; the local name keeps its case. */
export function splitAgentName(input: string): { domain: string; name: string } | null {
  const noScheme = input.trim().replace(/^https?:\/\//i, "");
  const idx = noScheme.indexOf("/@");
  if (idx < 1) return null;
  const domain = noScheme.slice(0, idx).toLowerCase();
  const afterMarker = noScheme.slice(idx + 2).replace(/\/+$/, "");
  const nextSlash = afterMarker.indexOf("/");
  const name = nextSlash === -1 ? afterMarker : afterMarker.slice(0, nextSlash);
  if (!domain || !name || name.includes("/@")) return null;
  return { domain, name };
}

type Role = "admin" | "owner" | "service";

export const api = {
  /** Unauthenticated liveness probe. Plain HTTP by design. */
  health: () => request<HealthResponse>("/api/health", { anonymous: true }),

  /** `server/info`: the service DID and the public facts shown before login. */
  serverInfo: (): Promise<ServerInfo> => getServiceInfo(),

  // ---- The service's own identity ----

  listIdentityGenerations: async (): Promise<IdentityGenerationsResponse> =>
    identityFromWire(
      await trustTask<IdentityList.Payload, IdentityList.Response>(T.identityList, {}),
    ),

  /**
   * Stop honouring a superseded generation immediately — the kill switch.
   * The key is dropped from the live secrets resolver before this returns.
   */
  retireIdentityGeneration: async (id: number): Promise<void> => {
    await trustTask<IdentityRetire.Payload, IdentityRetire.Response>(T.identityRetire, {
      generationId: id,
    });
  },

  // ---- DIDs ----

  /** Every slot the caller may see (an admin may name another `owner`),
   *  following `did/list`'s pages to the end. */
  listDids: async (owner?: string): Promise<DidRecord[]> => {
    const out: DidRecord[] = [];
    for (let offset = 0; ; ) {
      const page = await trustTask<DidList.Payload, DidList.Response>(T.didList, {
        ...(owner ? { owner } : {}),
        limit: DID_LIST_PAGE,
        ...(offset > 0 ? { offset } : {}),
      });
      out.push(...page.records.map(didRecordFromWire));
      offset += page.records.length;
      if (page.records.length === 0 || offset >= page.total) return out;
    }
  },

  /** A slot with its log summarised: `did/info` for the record, `did/log` for
   *  the summary (webvh parameters are read from the log itself). */
  getDid: async (mnemonic: string): Promise<DidDetailResponse> => {
    const [info, log] = await Promise.all([
      trustTask<DidInfo.Payload, DidInfo.Response>(T.didInfo, { mnemonic }),
      didLog(mnemonic, false).catch((e) => {
        // A slot with no published content has no log; that is not a failure.
        if (isRejection(e, "notFound")) return null;
        throw e;
      }),
    ]);
    return {
      ...didRecordFromWire(info.record),
      log: log ? logMetadataFromEntries(logEntriesFromWire(log)) : null,
    };
  },

  getDidLog: async (mnemonic: string): Promise<LogEntryInfo[]> =>
    logEntriesFromWire(await didLog(mnemonic, false)),

  /** The stored `did.jsonl`, verbatim. */
  getRawLog: async (mnemonic: string): Promise<string> =>
    (await didLog(mnemonic, true)).logContent ?? "",

  /** Claim a slot (`did/check-name` with `reserve: true`) — at `path`, or an
   *  auto-assigned one. Without `domain` the control plane uses the caller's
   *  default, then the system default. */
  createDid: async (path?: string, domain?: string): Promise<CreateDidResponse> => {
    const resp = await trustTask<DidCheckName.Payload, DidCheckName.Response>(T.didCheckName, {
      reserve: true,
      ...(path ? { path } : {}),
      ...(domain ? { domain } : {}),
    });
    if (!resp.reserved || !resp.record) {
      throw new ApiError(409, path ? `"${path}" is already taken` : "no slot could be reserved");
    }
    return { mnemonic: resp.record.mnemonic, didUrl: resp.record.didUrl ?? null };
  },

  changeOwner: async (mnemonic: string, newOwner: string): Promise<DidRecord> =>
    didRecordFromWire(
      (
        await trustTask<DidChangeOwner.Payload, DidChangeOwner.Response>(T.didChangeOwner, {
          mnemonic,
          newOwner,
        })
      ).record,
    ),

  /** Is `path` free? A read-only probe. */
  checkName: async (path: string, domain?: string): Promise<CheckNameResponse> => {
    const resp = await trustTask<DidCheckName.Payload, DidCheckName.Response>(T.didCheckName, {
      path,
      ...(domain ? { domain } : {}),
    });
    return { available: resp.available };
  },

  /** Is an agent name (`/@name`) free to claim on `domain`? Binding itself is
   *  a signed did.jsonl publish through the user's agent. */
  checkAgentName: async (name: string, domain?: string): Promise<AgentNameAvailability> => {
    const r = await trustTask<AgentNameCheck.Payload, AgentNameCheck.Response>(
      T.agentNameCheck,
      { name, ...(domain ? { domain } : {}) },
    );
    return { name: r.name, domain: r.domain, available: r.available, reserved: r.reserved };
  },

  /** DID -> its served agent names, batched. Only DIDs the caller may read
   *  and this service serves come back; read a miss and an empty list alike. */
  resolveAgentNames: async (dids: string[]): Promise<AgentNameResolveResponse> => {
    if (dids.length === 0) return { names: {} };
    const r = await trustTask<AgentNameResolve.Payload, AgentNameResolve.Response>(
      T.agentNameResolve,
      { dids: dids as [string, ...string[]] },
    );
    const names: Record<string, string[]> = {};
    for (const e of r.entries) names[e.did] = e.names;
    return { names };
  },

  /** Publish a signed `did.jsonl` to an existing slot (`did/register`). */
  uploadDid: async (mnemonic: string, log: string): Promise<void> => {
    await trustTask<DidRegister.Payload, DidRegister.Response>(T.didRegister, {
      path: mnemonic,
      method: "webvh",
      didData: log,
    });
  },

  /** Publish witness proofs (`did-witness.json`) for a slot. */
  uploadWitness: async (mnemonic: string, witnessJson: string): Promise<void> => {
    let witness: object;
    try {
      witness = JSON.parse(witnessJson);
    } catch (e) {
      throw new ApiError(400, `witness proofs are not valid JSON: ${(e as Error).message}`);
    }
    await trustTask<WitnessPublish.Payload, WitnessPublish.Response>(T.witnessPublish, {
      mnemonic,
      witness,
    });
  },

  deleteDid: async (mnemonic: string): Promise<void> => {
    await trustTask<DidDelete.Payload, DidDelete.Response>(T.didDelete, { mnemonic });
  },

  /** Discard the last log entry: roll back to `versionCount - 1`. */
  rollbackDid: async (mnemonic: string, versionCount: number): Promise<DidRecord> => {
    if (versionCount < 2) {
      throw new ApiError(400, "the first log entry cannot be rolled back");
    }
    const r = await trustTask<DidRollback.Payload, DidRollback.Response>(T.didRollback, {
      mnemonic,
      targetVersion: versionCount - 1,
    });
    return didRecordFromWire(r.record);
  },

  // ---- Stats ----

  getStats: async (mnemonic: string): Promise<DidStats> =>
    statsFromWire(
      await trustTask<StatsGet.Payload, StatsGet.Response>(T.statsGet, { mnemonic }),
    ),

  getServerStats: async (): Promise<ServerStats> =>
    statsFromWire(await trustTask<StatsGet.Payload, StatsGet.Response>(T.statsGet, {})),

  getServerTimeseries: async (
    range: TimeRange = "24h",
    domain?: string,
  ): Promise<TimeSeriesPoint[]> =>
    timeseriesFromWire(
      await trustTask<StatsTimeseries.Payload, StatsTimeseries.Response>(T.statsTimeseries, {
        range: timeRangeToWire(range),
        ...(domain ? { domain } : {}),
      }),
    ),

  getDidTimeseries: async (
    mnemonic: string,
    range: TimeRange = "24h",
  ): Promise<TimeSeriesPoint[]> =>
    timeseriesFromWire(
      await trustTask<StatsTimeseries.Payload, StatsTimeseries.Response>(T.statsTimeseries, {
        range: timeRangeToWire(range),
        mnemonic,
      }),
    ),

  // ---- The deployment ----

  getConfig: async (): Promise<ControlPlaneConfig> =>
    configFromWire(
      await trustTask<ServerConfig.Payload, ServerConfig.Response>(T.serverConfig, {}),
    ),

  /** Control plane + fleet + totals, for the dashboard. Admin. */
  getServicesOverview: async (): Promise<ServiceOverview> => {
    const [config, services, stats] = await Promise.all([
      api.getConfig(),
      api.listRegistry(),
      api.getServerStats(),
    ]);
    const count = (s: ServiceInstance["status"]) =>
      services.filter((i) => i.status === s).length;
    return {
      control: {
        version: config.softwareVersion,
        serverDid: config.controlDid,
        publicUrl: config.publicUrl,
        didcommEnabled: config.didcommEnabled,
        tspEnabled: config.tspEnabled,
        ...(config.advertisedServices ? { advertisedServices: config.advertisedServices } : {}),
        enabledMethods: config.enabledMethods,
      },
      services,
      aggregate: {
        totalServices: services.length,
        activeServices: count("active"),
        degradedServices: count("degraded"),
        unreachableServices: count("unreachable"),
        totalDids: stats.totalDids,
        totalResolves: stats.totalResolves,
        totalUpdates: stats.totalUpdates,
      },
    };
  },

  listRegistry: async (): Promise<ServiceInstance[]> =>
    (
      await trustTask<RegistryList.Payload, RegistryList.Response>(T.registryList, {})
    ).instances.map(serviceInstanceFromWire),

  /** Assign a hosting domain to a server instance; the control plane queues
   *  the directive to the edge. */
  assignDomainToServer: async (instanceId: string, domain: string): Promise<void> => {
    await trustTask<DomainAssign.Payload, DomainAssign.Response>(T.domainAssign, {
      instanceId,
      domain,
    });
  },

  /** Unassign; the edge schedules its purge after its grace period. */
  unassignDomainFromServer: async (instanceId: string, domain: string): Promise<void> => {
    await trustTask<DomainUnassign.Payload, DomainUnassign.Response>(T.domainUnassign, {
      instanceId,
      domain,
    });
  },

  /** Admin "Purge now" on one edge. Refused while the domain is still
   *  assigned to that edge (`stillAssigned`). */
  purgeDomainOnServer: async (instanceId: string, domain: string): Promise<void> => {
    await trustTask<RegistryPurgeDomain.Payload, RegistryPurgeDomain.Response>(
      T.registryPurgeDomain,
      { instanceId, domain },
    );
  },

  // ---- ACL ----
  //
  // The webvh-specific members travel under `ext["vnd.affinidi.webvh"]`.

  listAcl: async (): Promise<AclListResponse> => {
    const resp = await trustTask<AclList.Payload, AclList.Response>(T.aclList, {});
    return { entries: (resp.entries ?? []).map(aclEntryFromWire) };
  },

  /**
   * Turn what an operator typed into the ACL "Add Entry" field into a
   * DID. A DID is returned verbatim — `acl/grant` stores whatever
   * `subject` it is given, so this is the only place a name gets resolved
   * before it lands there.
   *
   * An agent name is resolved once, here: every DID this deployment hosts
   * is searched for one whose registry currently serves the name, and
   * `agent-name/resolve` — the same task an owner's console calls to show
   * a DID's addresses — confirms the binding is still live (enabled, and
   * claimed by the DID's current document) before it is accepted. The ACL
   * entry is then created against the DID, never the name: the name can
   * be released and re-claimed by someone else later, and that must not
   * silently move the grant (mirrors the removed REST route's
   * `resolve_did_or_agent_name`, which resolved once at write time for
   * the same reason).
   *
   * Throws when the input looks like an agent name but does not resolve
   * to a DID hosted here. Anything that doesn't look like an agent name
   * (including a malformed DID) is passed through unchanged — `acl/grant`
   * is left to refuse it in whatever shape it likes.
   */
  resolveAclSubject: async (input: string): Promise<string> => {
    const trimmed = input.trim();
    if (!looksLikeAgentName(trimmed)) return trimmed;
    const parsed = splitAgentName(trimmed);
    if (!parsed) {
      throw new ApiError(400, `'${trimmed}' is not a valid agent name`);
    }
    const served = `${parsed.domain}/@${parsed.name}`;
    const dids = await api.listDids();
    const hasDidId = (d: DidRecord): d is DidRecord & { didId: string } => d.didId !== null;
    const candidates = dids.filter(
      (d): d is DidRecord & { didId: string } =>
        hasDidId(d) &&
        d.domain === parsed.domain &&
        (d.agentNames ?? []).some((e) => e.enabled && e.name === parsed.name),
    );
    if (candidates.length > 0) {
      const { names } = await api.resolveAgentNames(candidates.map((d) => d.didId));
      const match = candidates.find((d) => names[d.didId]?.includes(served));
      if (match) return match.didId;
    }
    throw new ApiError(
      404,
      `agent name '${trimmed}' does not resolve to a DID hosted here — bind it first, or use the DID directly`,
    );
  },

  /**
   * `acl/grant`. `subject` is a DID, or an agent name hosted here
   * (`example.com/@alice`) — resolved to the DID it currently serves
   * before the grant is sent; see `resolveAclSubject`. `acl/grant`'s
   * scopes are explicit on the wire and the maintainer no longer infers
   * one (the removed REST route did, for a domain-less Owner) — a caller
   * granting Owner access is expected to pass `opts.domains` itself
   * (`Add Entry`'s default-domain-scope logic is what fills it in when
   * the operator hasn't chosen one). Omitting it falls back to `all`
   * here, matching the unrestricted default a bare Admin/Service grant
   * already gets.
   */
  createAcl: async (
    subject: string,
    role: Role,
    opts?: {
      label?: string;
      maxTotalSize?: number;
      maxDidCount?: number;
      domains?: DomainScope;
    },
  ): Promise<AclEntry> => {
    const did = await api.resolveAclSubject(subject);
    const resp = await trustTask<AclGrant.Payload, AclGrant.Response>(T.aclGrant, {
      entry: {
        subject: did,
        role,
        ...(opts?.label !== undefined ? { label: opts.label } : {}),
        ext: webvhAclExt(opts?.domains ?? { kind: "all" }, opts?.maxTotalSize, opts?.maxDidCount),
      },
    });
    return aclEntryFromWire(resp.entry);
  },

  /**
   * Change an entry. A role change is `acl/change-role` (state-checked
   * against the current role); anything else re-emits `acl/grant` with the
   * new metadata, which the maintainer treats as an idempotent update. A
   * combined update sends both, role first.
   */
  updateAcl: async (
    did: string,
    updates: {
      role?: Role;
      label?: string | null;
      maxTotalSize?: number | null;
      maxDidCount?: number | null;
      domains?: DomainScope;
    },
  ): Promise<AclEntry> => {
    let entry: AclEntry | null = null;
    const notFound = () => new ApiError(404, `subject ${did} not found in ACL`);

    if (updates.role !== undefined) {
      const current = await api.aclShow(did);
      if (!current) throw notFound();
      if (current.role !== updates.role) {
        const resp = await trustTask<AclChangeRole.Payload, AclChangeRole.Response>(
          T.aclChangeRole,
          { subject: did, fromRole: current.role, toRole: updates.role },
        );
        entry = aclEntryFromWire(resp.entry);
      } else {
        entry = current;
      }
    }

    const wantsMetadataUpdate =
      updates.label !== undefined ||
      updates.maxTotalSize !== undefined ||
      updates.maxDidCount !== undefined ||
      updates.domains !== undefined;

    if (wantsMetadataUpdate) {
      const base = entry ?? (await api.aclShow(did));
      if (!base) throw notFound();
      const label = updates.label === undefined ? base.label : updates.label;
      const resp = await trustTask<AclGrant.Payload, AclGrant.Response>(T.aclGrant, {
        entry: {
          subject: did,
          role: base.role,
          ...(label !== null && label !== undefined ? { label } : {}),
          ext: webvhAclExt(
            updates.domains ?? base.domains ?? { kind: "all" },
            updates.maxTotalSize === undefined ? base.max_total_size : updates.maxTotalSize,
            updates.maxDidCount === undefined ? base.max_did_count : updates.maxDidCount,
          ),
        },
      });
      entry = aclEntryFromWire(resp.entry);
    }

    if (!entry) {
      const refreshed = await api.aclShow(did);
      if (!refreshed) throw notFound();
      entry = refreshed;
    }
    return entry;
  },

  /** Single-entry lookup. `null` when the subject is not in the ACL. */
  aclShow: async (did: string): Promise<AclEntry | null> => {
    const resp = await trustTask<AclShow.Payload, AclShow.Response>(T.aclShow, { subject: did });
    return resp.entry ? aclEntryFromWire(resp.entry) : null;
  },

  deleteAcl: async (did: string): Promise<void> => {
    await trustTask<AclRevoke.Payload, AclRevoke.Response>(T.aclRevoke, { subject: did });
  },

  // ---- Hosting domains ----

  /** Every domain. Admin. */
  listDomains: async (): Promise<DomainListResponse> => {
    const r = await trustTask<DomainList.Payload, DomainList.Response>(T.domainList, {});
    return {
      domains: r.domains.map((d) => domainFromWire(d)),
      default: r.default ?? null,
    };
  },

  /** The caller's domains, with the caller's default. */
  listMyDomains: async (): Promise<DomainListResponse> => {
    const r = await trustTask<MeDomains.Payload, MeDomains.Response>(T.meDomains, {});
    return {
      domains: r.domains.map((d) => domainFromWire(d)),
      default: r.default ?? null,
    };
  },

  /** Create a domain; `setAsDefault` promotes it in the same call. Admin. */
  createDomain: async (input: {
    name: string;
    label?: string;
    setAsDefault?: boolean;
  }): Promise<DomainEntry> => {
    const r = await trustTask<DomainCreate.Payload, DomainCreate.Response>(T.domainCreate, {
      name: input.name,
      ...(input.label ? { label: input.label } : {}),
      ...(input.setAsDefault ? { setAsDefault: true } : {}),
    });
    return domainFromWire(r.entry);
  },

  disableDomain: async (name: string): Promise<DomainEntry> =>
    domainFromWire(
      (
        await trustTask<DomainSetState.Payload, DomainSetState.Response>(T.domainSetState, {
          name,
          state: "disabled",
        })
      ).entry,
    ),

  enableDomain: async (name: string): Promise<DomainEntry> =>
    domainFromWire(
      (
        await trustTask<DomainSetState.Payload, DomainSetState.Response>(T.domainSetState, {
          name,
          state: "active",
        })
      ).entry,
    ),

  setDefaultDomain: async (name: string): Promise<DomainEntry> =>
    domainFromWire(
      (
        await trustTask<DomainSetDefault.Payload, DomainSetDefault.Response>(
          T.domainSetDefault,
          { name },
        )
      ).entry,
    ),

  /**
   * Force-delete a disabled domain now, ahead of its grace window. Refused
   * while the domain is active or the default.
   *
   * Needs a stepped-up (`aal2`) session. A passkey login already is one; a
   * wallet session is stepped up through the wallet when the control plane
   * asks for it, and the purge is then sent once more.
   *
   * `purgeServers` also sends the purge to every edge serving the domain.
   */
  deleteDomain: async (name: string, opts?: { purgeServers?: boolean }): Promise<void> => {
    const purge = () =>
      trustTask<DomainPurge.Payload, DomainPurge.Response>(T.domainPurge, {
        name,
        ...(opts?.purgeServers ? { purgeServers: true } : {}),
      });
    try {
      await purge();
    } catch (e) {
      if (!isRejection(e, "stepUpRequired")) throw e;
      await api.stepUp();
      await purge();
    }
  },

  /**
   * Sign out: end this session at the control plane, then forget it here.
   *
   * Clearing the browser's copy alone would leave the session, and any session
   * key bound to it, live until it expires. `auth/revoke-session` deletes the
   * row, and every later request made with the token or the key is refused.
   * It is signed with the session key, so signing out never prompts the wallet.
   * A session with no bound key (a proxy login) is cleared locally only,
   * because revoking it would cost a wallet prompt to sign out.
   *
   * Best effort. A failed revoke still signs this browser out; the session
   * then lapses at its expiry.
   */
  logout: async (): Promise<void> => {
    const token = getToken();
    const sessionId = getSessionId();
    try {
      if (!hasSessionKeypair()) await restoreSessionKeypair();
      if (sessionId && hasSessionKeypair()) {
        await trustTask<RevokeSession.Payload, RevokeSession.Response>(T.revokeSession, {
          sessionId,
          reason: "logout",
        });
      }
    } catch {
      // Signed out locally regardless; see above.
    } finally {
      // Unless a new sign-in has replaced this session while the revoke was
      // in flight: clearing then would drop the new session's token and key.
      if (getToken() === token) clearToken();
    }
  },

  /**
   * Raise this session to `aal2` through the wallet: the wallet sends
   * `auth/step-up/start`, verifies the signed approve-request it gets back,
   * asks the user, answers with a signed `approve-response`, and renews the
   * session with `auth/refresh`. The new tokens replace the old ones here.
   *
   * Only a wallet session can do this; a passkey session is `aal2` from login.
   */
  stepUp: async (): Promise<void> => {
    const wallet = typeof window !== "undefined" ? window.vtaWallet : undefined;
    const accessToken = getToken();
    const refreshToken = getRefreshToken();
    const sessionId = getSessionId();
    if (getAuthMethod() !== "wallet" || !wallet?.stepUpVta) {
      throw new ApiError(
        403,
        "This action needs a stepped-up session. Sign in again with a passkey, or with a wallet that supports step-up.",
      );
    }
    if (!accessToken || !refreshToken || !sessionId) {
      throw new ApiError(401, "No session to step up — sign in again.");
    }
    const { serviceDid } = await getServiceInfo();
    const result = await wallet.stepUpVta({
      baseUrl: getApiBase(),
      rpDid: serviceDid,
      accessToken,
      refreshToken,
      sessionId,
    });
    setToken(result.accessToken);
    setRefreshToken(result.refreshToken);
  },

  // ---- Passkey login (Trust Tasks) ----

  /** Open a login ceremony. Sent anonymously: opening one authorises nothing. */
  passkeyLoginStart: async (): Promise<LoginStartResponse> => {
    const r = await trustTask<LoginStart.Payload, LoginStart.Response>(
      T.loginStart,
      { purpose: "login" },
      { signer: "none", anonymous: true },
    );
    return { authId: r.authId, options: r.options };
  },

  /**
   * Finish the ceremony. The document is signed by a fresh session key as its
   * own `did:key`; the control plane binds the new session to exactly that
   * key, so every later request in the session must be signed by it. The
   * private key never leaves this browser.
   */
  passkeyLoginFinish: async (
    authId: string,
    credential: LoginFinish.Payload["credential"],
  ): Promise<LoginTokens> => {
    const r = await trustTask<LoginFinish.Payload, LoginFinish.Response>(
      T.loginFinish,
      { authId, credential },
      { signer: "fresh-session-key", anonymous: true },
    );
    if (r.purpose !== "login" || !r.tokens) {
      throw new ApiError(502, "the control plane finished a login without issuing a session");
    }
    return { accessToken: r.tokens.accessToken, refreshToken: r.tokens.refreshToken ?? null };
  },

  // ---- Passkey enrolment (Trust Tasks) ----

  /**
   * Issue an invite (administrator). A `session` invite enrols a login passkey
   * with `role`; a `stepUp` invite a step-up-only passkey, which carries no
   * role and never signs in.
   */
  createInvite: async (
    did: string,
    role: Role,
    purpose: InvitePurpose = "session",
  ): Promise<CreateInviteResponse> => {
    const r = await trustTask<Invite.Payload, Invite.Response>(T.invite, {
      subject: did,
      ...(purpose === "session" ? { role } : { purpose }),
    });
    return {
      inviteUrl: r.invite.url,
      claimCode: r.claimCode,
      subject: r.subject,
      purpose: r.purpose,
      expiresAt: Math.floor(Date.parse(r.expiresAt) / 1000),
    };
  },

  /**
   * Present an invite's token (from its URL) and its claim code (delivered
   * separately). Sent anonymously and unsigned: the invitee has no key the
   * control plane knows, and the two halves are the authorisation.
   */
  redeemStart: async (token: string, claimCode: string): Promise<RedeemStartResponse> =>
    trustTask<RedeemStart.Payload, RedeemStart.Response>(
      T.redeemStart,
      { token, claimCode },
      { signer: "none", anonymous: true },
    ),

  /** Bind the new passkey (and, where asked, prove an existing one). */
  redeemFinish: async (
    enrollmentId: string,
    credential: RedeemFinish.Payload["credential"],
    uvCredential?: RedeemFinish.Payload["uvCredential"],
    deviceLabel?: string,
  ): Promise<RedeemFinishResponse> =>
    trustTask<RedeemFinish.Payload, RedeemFinish.Response>(
      T.redeemFinish,
      {
        enrollmentId,
        credential,
        // Only the members given: an `undefined` member cannot be
        // canonicalised, and the spec reads an absent one as "none".
        ...(uvCredential ? { uvCredential } : {}),
        ...(deviceLabel ? { deviceLabel } : {}),
      },
      { signer: "none", anonymous: true },
    ),

  // ---- Enrolment invites (Trust Tasks) ----

  listInvites: async (): Promise<InviteListResponse> => {
    const r = await trustTask<InviteList.Payload, InviteList.Response>(T.inviteList, {});
    return { invites: r.invites.map(inviteFromWire) };
  },

  /** Change a pending invite's role, or push its expiry out. */
  updateInvite: async (
    inviteId: string,
    updates: { role?: Role; expiresAt?: string; extendBy?: number },
  ): Promise<InviteListItem> => {
    // Only the members actually given: a document carrying an `undefined`
    // member cannot be canonicalised for its proof, and the spec reads an
    // absent member as "unchanged".
    const r = await trustTask<InviteUpdate.Payload, InviteUpdate.Response>(T.inviteUpdate, {
      inviteId,
      ...(updates.role !== undefined ? { role: updates.role } : {}),
      ...(updates.expiresAt !== undefined ? { expiresAt: updates.expiresAt } : {}),
      ...(updates.extendBy !== undefined ? { extendBy: updates.extendBy } : {}),
    });
    return inviteFromWire(r.invite);
  },

  revokeInvite: async (inviteId: string): Promise<void> => {
    await trustTask<InviteRevoke.Payload, InviteRevoke.Response>(T.inviteRevoke, { inviteId });
  },
};
