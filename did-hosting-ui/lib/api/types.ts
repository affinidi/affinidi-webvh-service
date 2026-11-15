/**
 * The view models the screens render — what `wire.ts` projects each Trust
 * Task reply into. Shared by every `api/*` family module.
 */

import type * as LoginStart from "../trust-tasks/auth/passkey/login/start/0.2/payload";
import type * as RedeemStart from "../trust-tasks/auth/passkey/enroll/redeem/start/0.1/payload";
import type * as RedeemFinish from "../trust-tasks/auth/passkey/enroll/redeem/finish/0.1/payload";
import type * as PasskeyRevokeStart from "../trust-tasks/auth/passkey/revoke/start/0.2/payload";
import { type ScidAliasState } from "../scid-alias";

export interface HealthResponse {
  status: string;
  version: string;
}

/** DID hosting method tag carried on every DidRecord. */
export type DidMethod = "webvh" | "web" | "webs" | "webplus" | string;

/** What `changeOwner` did: `offer` is set when the DID did not move yet and
 *  waits for its recipient to accept. */
export interface OwnerChangeResult {
  record: DidRecord;
  offer?: { newOwner: string; expiresAt: string };
}

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
  /** The latest document's did:scid alias state, from `did/info` only —
   *  derived by the control plane (see `lib/scid-alias`). */
  scidAlias?: ScidAliasState;
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
  /** The log's entries, as read for `log` (empty when there is none). */
  entries: LogEntryInfo[];
}

/** What a `did/list` page is narrowed to (all server-side). */
export interface DidListQuery {
  /** Admin only: one owner's slots. */
  owner?: string;
  /** Only slots hosted under this domain. */
  domain?: string;
  /** Case-insensitive substring of the name, DID or an agent name. */
  search?: string;
  /** The slot holding this agent name (no `@`) on `domain`, which it needs. */
  agentName?: string;
  limit?: number;
  /** A previous page's `nextCursor`, for the same filters. */
  cursor?: string;
}

/** One `did/list` page. */
export interface DidListPage {
  records: DidRecord[];
  /** Present while more may follow; a short page can still have one. */
  nextCursor?: string;
}

/**
 * A did:webvh log entry's `parameters`, as far as the console reads them.
 * Unverified wire data, so every member is `unknown` and checked where it is
 * read. Parameters are cumulative: an entry names only what it changes.
 */
export interface WebvhParameters {
  method?: unknown;
  portable?: unknown;
  ttl?: unknown;
  nextKeyHashes?: unknown;
  deactivated?: unknown;
  watchers?: unknown;
  witness?: unknown;
  [member: string]: unknown;
}

/** A log entry's DID document, as far as the console reads one. */
export interface DidDocumentState {
  id?: unknown;
  alsoKnownAs?: unknown;
  [member: string]: unknown;
}

export interface LogEntryInfo {
  versionId: string | null;
  versionTime: string | null;
  state: DidDocumentState | null;
  parameters: WebvhParameters | null;
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
  role: "admin" | "owner" | "service" | "metricsReader";
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
  /** Width of the point, in seconds: the response's `bucketSeconds`. A DID
   *  without 5-minute statistics is charted hourly (or daily over 30 days),
   *  so this is not fixed by the range. */
  seconds: number;
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
  // Includes `metricsReader` so a stale/forged invite carrying it is shown as
  // itself rather than silently folded into another role — see `role()` in
  // `wire.ts`. New invites can no longer be created with it (server-refused).
  role: "admin" | "owner" | "service" | "metricsReader";
  createdAt: number;
  expiresAt: number;
  expired: boolean;
}

export interface InviteListResponse {
  invites: InviteListItem[];
}

/** A passkey already bound to a subject — the auth service's own management
 *  view (`auth/passkey/list`, `auth/passkey/admin-list`), never a WebAuthn
 *  dictionary. `credentialId` is opaque: echoed verbatim to
 *  `revokePasskeyStart`, never parsed. */
export interface PasskeyCredential {
  credentialId: string;
  deviceLabel: string | null;
  registeredAt: number;
  lastUsedAt: number | null;
  transports: string[];
}

/** The caller's own re-authentication ceremony for `revoke/finish`. */
export interface RevokePasskeyStartResponse {
  revocationId: string;
  uvOptions: PasskeyRevokeStart.Response["uvOptions"];
}

export interface RevokePasskeyFinishResponse {
  credentialId: string;
  subject: string;
  purpose: InvitePurpose;
  revokedAt: number;
  remaining: number;
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

/** The ACL roles this control plane grants. */
export type Role = "admin" | "owner" | "service" | "metricsReader";
