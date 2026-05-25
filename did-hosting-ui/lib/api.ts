/** Typed API client for the did-hosting-control REST API. */

import {
  clearSessionKeypair,
  generateSessionKeypair,
  hasSessionKeypair,
  restoreSessionKeypair,
  signEnvelope,
} from "./session-key";

export interface HealthResponse {
  status: string;
  version: string;
}

/** DID hosting method tag carried on every DidRecord (v0.7+). */
export type DidMethod = "webvh" | "web" | "webs" | "webplus" | string;

export interface DidRecord {
  mnemonic: string;
  owner: string;
  createdAt: number;
  updatedAt: number;
  versionCount: number;
  didId: string | null;
  totalResolves: number;
  /** Resolution method ("webvh" / "web"). Filled by M-01 on legacy records. */
  method?: DidMethod;
  /** Hosting domain. Filled by M-01 on legacy records. */
  domain?: string;
}

// ---------------------------------------------------------------------------
// Multi-domain types (v0.7)
// ---------------------------------------------------------------------------

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

/** Server-side `DomainEntry` (`KS_DOMAINS`). The wire is snake_case (the
 *  Rust struct has no `rename_all`); this interface is camelCase and the
 *  raw response is run through `normalizeDomain()` at the API boundary
 *  before reaching the UI. */
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
  /** Unix seconds when disable was called. Null while Active. The
   *  domain + every hosted DID is permanently removed at `purgeAt`
   *  unless the operator re-enables before then. */
  disabledAt: number | null;
  /** Unix seconds at which the disabled domain becomes eligible for
   *  the background purge sweep. Null while Active. */
  purgeAt: number | null;
}

export interface DomainListResponse {
  domains: DomainEntry[];
  /** Currently-elected system default; may be null on a fresh install. */
  default: string | null;
}

// snake_case → camelCase normalization at the wire boundary. The server's
// Rust DomainEntry has no #[serde(rename_all = "camelCase")] attribute and
// adding it would invalidate already-stored fjall records, so we hydrate
// here instead. Accepts either case (forward-compat if the server ever
// flips).
function normalizeBranding(b: any): DomainBranding | null {
  if (!b) return null;
  return {
    logoUrl: b.logoUrl ?? b.logo_url ?? null,
    primaryColor: b.primaryColor ?? b.primary_color ?? null,
    displayName: b.displayName ?? b.display_name ?? null,
  };
}
function normalizeQuota(q: any): DomainQuota | null {
  if (!q) return null;
  return {
    maxDids: q.maxDids ?? q.max_dids ?? null,
    maxBytes: q.maxBytes ?? q.max_bytes ?? null,
  };
}
function normalizeDomain(raw: any): DomainEntry {
  return {
    name: raw.name,
    label: raw.label ?? null,
    scheme: raw.scheme,
    status: raw.status,
    createdAt: raw.createdAt ?? raw.created_at,
    defaultDomain: raw.defaultDomain ?? raw.default_domain ?? false,
    branding: normalizeBranding(raw.branding),
    witnesses: raw.witnesses ?? null,
    watchers: raw.watchers ?? null,
    quota: normalizeQuota(raw.quota),
    wellKnownEnabled: raw.wellKnownEnabled ?? raw.well_known_enabled ?? false,
    disabledAt: raw.disabledAt ?? raw.disabled_at ?? null,
    purgeAt: raw.purgeAt ?? raw.purge_at ?? null,
  };
}
function normalizeDomainList(raw: any): DomainListResponse {
  return {
    domains: (raw.domains ?? []).map(normalizeDomain),
    default: raw.default ?? null,
  };
}

/** Per-ACL `DomainScope`. Tagged with `kind` per spec §3 wire shape. */
export type DomainScope =
  | { kind: "all" }
  | { kind: "allowed"; domains: string[] }
  | { kind: "allowed_with_default"; domains: string[]; default: string };

export interface ServiceInstance {
  instanceId: string;
  serviceType: "server" | "witness" | "watcher";
  label: string | null;
  url: string;
  status: "active" | "degraded" | "unreachable";
  lastHealthCheck: number | null;
  registeredAt: number;
  metadata: any;
  /** v0.7+ capability declaration. */
  enabledMethods: string[];
  servedDomains: string[];
  protocolVersion: string;
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

export interface ServicesResponse {
  watcherUrls: string[];
}

export interface WatcherSyncStatus {
  watcherUrl: string;
  lastSyncedVersionId: string | null;
  lastSyncedAt: number | null;
  lastError: string | null;
  ok: boolean;
}

export interface DidDetailResponse {
  mnemonic: string;
  createdAt: number;
  updatedAt: number;
  versionCount: number;
  didId: string | null;
  owner: string;
  log: LogMetadata | null;
  watcherSync: WatcherSyncStatus[] | null;
  /** v0.7: hosting method (`webvh` / `web`). Omitted on legacy records. */
  method?: string;
  /** v0.7: hosting domain. Omitted on legacy records pre-M-01. */
  domain?: string;
}

export interface LogEntryInfo {
  versionId: string | null;
  versionTime: string | null;
  state: Record<string, any> | null;
  parameters: Record<string, any> | null;
}

export interface CreateDidResponse {
  mnemonic: string;
  didUrl: string;
}

export interface ChangeOwnerResponse {
  mnemonic: string;
  owner: string;
  updatedAt: number;
}

export interface CheckNameResponse {
  available: boolean;
  path: string;
}

export interface AclEntry {
  did: string;
  role: "admin" | "owner" | "service";
  label: string | null;
  created_at: number;
  max_total_size: number | null;
  max_did_count: number | null;
  /** Per-ACL `DomainScope` (v0.7). Optional for forward-compat — a
   * v0.6 store with no scope field deserialises as `{ kind: "all" }`. */
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

export interface ServerStats {
  totalDids: number;
  totalResolves: number;
  totalUpdates: number;
  lastResolvedAt: number | null;
  lastUpdatedAt: number | null;
}

export interface TimeSeriesPoint {
  timestamp: number;
  resolves: number;
  updates: number;
}

export type TimeRange = "1h" | "24h" | "7d" | "30d";

// Service overview types
export interface ServiceOverview {
  control: ControlInfo;
  services: ServiceInfo[];
  aggregate: AggregateStats;
}

export interface ControlInfo {
  version: string;
  serverDid: string | null;
  publicUrl: string | null;
  didcommEnabled: boolean;
  totalLocalDids: number;
}

export interface ServiceInfo {
  instanceId: string;
  serviceType: string;
  label: string | null;
  url: string;
  status: string;
  lastHealthCheck: number | null;
  registeredAt: number;
  did: string | null;
  stats: ServiceStats | null;
}

export interface ServiceStats {
  totalDids: number;
  totalResolves: number;
  totalUpdates: number;
  lastResolvedAt: number | null;
  lastUpdatedAt: number | null;
}

export interface AggregateStats {
  totalServices: number;
  activeServices: number;
  degradedServices: number;
  unreachableServices: number;
  totalDids: number;
  totalResolves: number;
  totalUpdates: number;
}

export interface TokenResponse {
  session_id: string;
  access_token: string;
  access_expires_at: number;
  refresh_token: string;
  refresh_expires_at: number;
}

export interface EnrollStartResponse {
  registration_id: string;
  options: any;
}

export interface LoginStartResponse {
  auth_id: string;
  options: any;
}

export interface CreateInviteResponse {
  token: string;
  enrollment_url: string;
  expires_at: number;
}

export interface InviteListItem {
  token: string;
  did: string;
  role: "admin" | "owner" | "service";
  created_at: number;
  expires_at: number;
  enrollment_url: string;
  expired: boolean;
}

export interface InviteListResponse {
  invites: InviteListItem[];
}

export interface ControlPlaneConfig {
  controlDid: string | null;
  mediatorDid: string | null;
  publicUrl: string | null;
  didHostingUrl: string | null;
  didcommEnabled: boolean;
  restApiEnabled: boolean;
  listenAddress: string;
  vtaUrl: string | null;
  vtaDid: string | null;
  deploymentMode: string;
  healthCheckIntervalSecs: number;
  configuredInstances: number;
  accessTokenExpiry: number;
  refreshTokenExpiry: number;
  passkeyEnrollmentTtl: number;
  dataDir: string;
  logLevel: string;
  logFormat: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const TOKEN_KEY = "webvh_token";

/** Which auth path produced the current session. Trust-task signing
 *  branches on this: `"wallet"` calls `window.vtaWallet.signTrustTask` (the
 *  holder did:peer is the signing identity); anything else uses the
 *  ephemeral session keypair the passkey-login flow generates. */
export type AuthMethod = "passkey" | "wallet";
const AUTH_METHOD_KEY = "webvh_auth_method";

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // ignore in non-browser contexts
  }
}

export function getAuthMethod(): AuthMethod | null {
  try {
    const v = localStorage.getItem(AUTH_METHOD_KEY);
    return v === "passkey" || v === "wallet" ? v : null;
  } catch {
    return null;
  }
}

export function setAuthMethod(method: AuthMethod): void {
  try {
    localStorage.setItem(AUTH_METHOD_KEY, method);
  } catch {
    // ignore
  }
}

export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(AUTH_METHOD_KEY);
  } catch {
    // ignore
  }
  // Drop the session keypair from both memory and IndexedDB.
  // Fire-and-forget; logout shouldn't block on storage.
  clearSessionKeypair();
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...options, headers });

  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
      window.dispatchEvent(new Event("webvh:unauthorized"));
    }
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  // Guard against HTML fallback responses (e.g., SPA catch-all returning index.html)
  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new ApiError(
      res.status,
      `Expected JSON response but got ${contentType || "unknown content type"} — is the API endpoint available?`,
    );
  }

  return res.json() as Promise<T>;
}

async function requestText(
  path: string,
  options: RequestInit = {},
): Promise<string> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...options, headers });

  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
      window.dispatchEvent(new Event("webvh:unauthorized"));
    }
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }

  return res.text();
}

/** Response shape of `GET /api/server-info`. */
export interface ServerInfoResponse {
  /** The server's DID — used as the `recipient` / audience-binding value on
   *  signed trust-task envelopes (SPEC §4.8.2). `null` when the operator
   *  hasn't configured one (signed trust tasks will then be refused by the
   *  server). */
  server_did: string | null;
  /** Soft-delete grace period applied when a domain is disabled, in
   *  seconds. The Domains screen reads this to render the deletion
   *  countdown copy. `null` if config is missing/unparseable — UI
   *  falls back to a generic warning without a specific duration. */
  disable_purge_grace_seconds: number | null;
}

// Cache the server-info response for the lifetime of the tab. The server's
// DID is stable per-deployment + already published in the server's did.jsonl,
// so we never need to re-fetch unless we hit a config error somewhere.
let cachedServerInfo: ServerInfoResponse | null = null;
async function getServerInfo(): Promise<ServerInfoResponse> {
  if (cachedServerInfo) return cachedServerInfo;
  cachedServerInfo = await request<ServerInfoResponse>("/api/server-info");
  return cachedServerInfo;
}

export const api = {
  health: () => request<HealthResponse>("/api/health"),
  serverInfo: getServerInfo,

  listDids: (owner?: string) => {
    const params = owner ? `?owner=${encodeURIComponent(owner)}` : "";
    return request<DidRecord[]>(`/api/dids${params}`);
  },

  getDid: (mnemonic: string) =>
    request<DidDetailResponse>(`/api/dids/${mnemonic}`),

  getDidLog: (mnemonic: string) =>
    request<LogEntryInfo[]>(`/api/log/${mnemonic}`),

  createDid: (
    path?: string,
    force?: boolean,
    /** Optional explicit domain. Omitted → daemon's T34 resolver picks
     * the caller's ACL default → system default → 400. */
    domain?: string,
  ) =>
    request<CreateDidResponse>("/api/dids", {
      method: "POST",
      ...(path || force || domain
        ? {
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path, force: force ?? false, domain }),
          }
        : {}),
    }),

  changeOwner: (mnemonic: string, newOwner: string) =>
    request<ChangeOwnerResponse>(`/api/owner/${mnemonic}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ new_owner: newOwner }),
    }),

  checkName: (path: string, domain?: string) =>
    request<CheckNameResponse>("/api/dids/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, domain }),
    }),

  uploadDid: (mnemonic: string, body: string) =>
    request<void>(`/api/dids/${mnemonic}`, {
      method: "PUT",
      headers: { "Content-Type": "text/plain" },
      body,
    }),

  uploadWitness: (mnemonic: string, body: string) =>
    request<void>(`/api/witness/${mnemonic}`, {
      method: "PUT",
      headers: { "Content-Type": "text/plain" },
      body,
    }),

  deleteDid: (mnemonic: string) =>
    request<void>(`/api/dids/${mnemonic}`, { method: "DELETE" }),

  rollbackDid: (mnemonic: string) =>
    request<DidDetailResponse>(`/api/rollback/${mnemonic}`, { method: "POST" }),

  getRawLog: (mnemonic: string) => requestText(`/api/raw/${mnemonic}`),

  getServices: () => request<ServicesResponse>("/api/services"),

  getStats: (mnemonic: string) =>
    request<DidStats>(`/api/stats/${mnemonic}`),

  getServerStats: () => request<ServerStats>("/api/stats"),

  getServicesOverview: () => request<ServiceOverview>("/api/services/overview"),

  getServerTimeseries: (range: TimeRange = "24h") =>
    request<TimeSeriesPoint[]>(`/api/timeseries?range=${range}`),

  getDidTimeseries: (mnemonic: string, range: TimeRange = "24h") =>
    request<TimeSeriesPoint[]>(`/api/timeseries/${mnemonic}?range=${range}`),

  // ---- ACL via Trust Tasks (v0.7.0+) ----
  //
  // The four methods below post to `/api/trust-tasks` carrying typed
  // `acl/*` envelopes. The wire shape comes from the registry at
  // https://trusttasks.org/spec/acl/; webvh-specific fields land
  // inside `payload.entry.ext.vnd.affinidi.webvh.*`.
  //
  // The methods preserve the same TypeScript surface the UI screens
  // already use (in, out, error semantics) so the ACL admin page
  // didn't have to change shape — the wire format swap is invisible
  // to the caller. The legacy `/api/acl/*` REST routes still exist
  // on the server (deprecation-tagged); we no longer hit them from
  // the UI. They are removed in v0.8.0.
  //
  // **Proofs**: v0.7.0 emits *unsigned* envelopes — the browser has
  // no Data Integrity signing infrastructure today. The server's
  // bearer JWT auth establishes the caller's identity end-to-end on
  // the §4.8.1 transport channel. Operators with backend-only
  // callers can flip `trust_tasks.enforce_proofs = true` server-side
  // to require signed envelopes; v0.8.0 ships the session-key
  // protocol that lets the UI sign too.

  listAcl: async (): Promise<AclListResponse> => {
    const resp = await trustTask<AclListEnvelopePayload, AclListResponsePayload>(
      "https://trusttasks.org/spec/acl/list/0.1",
      { /* no filters; defaults to everything paged */ },
    );
    return {
      entries: (resp.entries ?? []).map(specEntryToLocal),
    };
  },

  createAcl: async (
    did: string,
    role: "admin" | "owner" | "service",
    opts?: {
      label?: string;
      maxTotalSize?: number;
      maxDidCount?: number;
      /** Optional DomainScope. Omit to inherit the daemon default
       * (Owner → AllowedWithDefault on system default; Admin/Service → All). */
      domains?: DomainScope;
    },
  ): Promise<AclEntry> => {
    // The webvh `vnd.affinidi.webvh` ext namespace requires `domains`
    // because the auth path uses it on every request. Build a default
    // when the caller didn't supply one; the server reshapes `All`
    // appropriately for Admin/Service roles.
    const webvhExt: Record<string, any> = {
      domains: opts?.domains ?? { kind: "all" },
    };
    const quota: Record<string, number> = {};
    if (typeof opts?.maxTotalSize === "number") {
      quota.maxTotalSize = opts.maxTotalSize;
    }
    if (typeof opts?.maxDidCount === "number") {
      quota.maxDidCount = opts.maxDidCount;
    }
    if (Object.keys(quota).length > 0) {
      webvhExt.quota = quota;
    }

    const resp = await trustTask<AclGrantPayload, AclEntryResponsePayload>(
      "https://trusttasks.org/spec/acl/grant/0.1",
      {
        entry: {
          subject: did,
          role,
          ...(opts?.label !== undefined ? { label: opts.label } : {}),
          ext: { "vnd.affinidi.webvh": webvhExt },
        },
      },
    );
    return specEntryToLocal(resp.entry);
  },

  updateAcl: async (
    did: string,
    updates: {
      role?: "admin" | "owner" | "service";
      label?: string | null;
      maxTotalSize?: number | null;
      maxDidCount?: number | null;
      domains?: DomainScope;
    },
  ): Promise<AclEntry> => {
    // v0.7's `updateAcl` was a kitchen-sink PUT that could change
    // role + label + quotas + domains in one call. The acl/* spec
    // family splits these:
    //
    //   - role change   → acl/change-role/0.1 (state-checked)
    //   - other fields  → re-emit acl/grant/0.1 with the new entry
    //     shape (the maintainer treats same-role grants as
    //     idempotent updates of the metadata fields)
    //
    // We surface the same single `updateAcl(did, updates)` call by
    // sequencing the two tasks as needed. A change-role-only update
    // hits exactly one trust-task; a metadata-only update hits one;
    // a combined update hits two with the role transition first.
    let entry: AclEntry | null = null;

    if (updates.role !== undefined) {
      // Need the existing role for the state-checked transition.
      const current = await api.aclShow(did);
      if (!current) {
        throw new ApiError(404, `subject ${did} not found in ACL`);
      }
      if (current.role !== updates.role) {
        const resp = await trustTask<AclChangeRolePayload, AclEntryResponsePayload>(
          "https://trusttasks.org/spec/acl/change-role/0.1",
          {
            subject: did,
            fromRole: current.role,
            toRole: updates.role,
          },
        );
        entry = specEntryToLocal(resp.entry);
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
      if (!base) {
        throw new ApiError(404, `subject ${did} not found in ACL`);
      }
      const webvhExt: Record<string, any> = {
        domains: updates.domains ?? base.domains ?? { kind: "all" },
      };
      const quota: Record<string, number> = {};
      const finalMaxTotalSize =
        updates.maxTotalSize === undefined
          ? base.max_total_size
          : updates.maxTotalSize;
      const finalMaxDidCount =
        updates.maxDidCount === undefined
          ? base.max_did_count
          : updates.maxDidCount;
      if (typeof finalMaxTotalSize === "number") {
        quota.maxTotalSize = finalMaxTotalSize;
      }
      if (typeof finalMaxDidCount === "number") {
        quota.maxDidCount = finalMaxDidCount;
      }
      if (Object.keys(quota).length > 0) {
        webvhExt.quota = quota;
      }

      const finalLabel =
        updates.label === undefined ? base.label : updates.label;

      const resp = await trustTask<AclGrantPayload, AclEntryResponsePayload>(
        "https://trusttasks.org/spec/acl/grant/0.1",
        {
          entry: {
            subject: did,
            role: base.role,
            ...(finalLabel !== null && finalLabel !== undefined
              ? { label: finalLabel }
              : {}),
            ext: { "vnd.affinidi.webvh": webvhExt },
          },
        },
      );
      entry = specEntryToLocal(resp.entry);
    }

    if (!entry) {
      // Shouldn't happen: caller invoked update with no changes.
      const refreshed = await api.aclShow(did);
      if (!refreshed) {
        throw new ApiError(404, `subject ${did} not found in ACL`);
      }
      entry = refreshed;
    }
    return entry;
  },

  /** Single-entry lookup (v0.7.0). Returns `null` when the subject
   * is not in the ACL — distinct from a server error. */
  aclShow: async (did: string): Promise<AclEntry | null> => {
    const resp = await trustTask<AclShowPayload, AclShowResponsePayload>(
      "https://trusttasks.org/spec/acl/show/0.1",
      { subject: did },
    );
    return resp.entry ? specEntryToLocal(resp.entry) : null;
  },

  deleteAcl: async (did: string): Promise<void> => {
    await trustTask<AclRevokePayload, AclRevokeResponsePayload>(
      "https://trusttasks.org/spec/acl/revoke/0.1",
      { subject: did },
    );
  },

  // ---- Multi-domain (v0.7) ----

  /** GET /api/domains — Admin only. */
  listDomains: () =>
    request<any>("/api/domains").then(normalizeDomainList),

  /** GET /api/me/domains — caller-scoped subset; returns the caller's
   * default in the `default` field (falls back to the system default
   * when the caller's scope is `All` / `Allowed` without a default). */
  listMyDomains: () =>
    request<any>("/api/me/domains").then(normalizeDomainList),

  /** POST /api/domains — Admin creates a new domain. `setAsDefault`
   * promotes it to the system default in the same call. */
  createDomain: (input: {
    name: string;
    label?: string;
    scheme?: DomainUrlScheme;
    branding?: DomainBranding;
    witnesses?: string[];
    watchers?: string[];
    quota?: DomainQuota;
    wellKnownEnabled?: boolean;
    setAsDefault?: boolean;
  }) =>
    request<any>("/api/domains", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: input.name,
        label: input.label,
        scheme: input.scheme,
        branding: input.branding,
        witnesses: input.witnesses,
        watchers: input.watchers,
        quota: input.quota,
        well_known_enabled: input.wellKnownEnabled,
        set_as_default: input.setAsDefault,
      }),
    }).then(normalizeDomain),

  /** PUT /api/domains/{name} — Admin updates metadata. Status,
   * default-flag, and created_at are preserved. */
  updateDomain: (
    name: string,
    updates: Partial<{
      label: string;
      scheme: DomainUrlScheme;
      branding: DomainBranding;
      witnesses: string[];
      watchers: string[];
      quota: DomainQuota;
      wellKnownEnabled: boolean;
    }>,
  ) =>
    request<any>(`/api/domains/${encodeURIComponent(name)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: updates.label,
        scheme: updates.scheme,
        branding: updates.branding,
        witnesses: updates.witnesses,
        watchers: updates.watchers,
        quota: updates.quota,
        well_known_enabled: updates.wellKnownEnabled,
      }),
    }).then(normalizeDomain),

  disableDomain: (name: string) =>
    request<any>(`/api/domains/${encodeURIComponent(name)}/disable`, {
      method: "POST",
    }).then(normalizeDomain),

  enableDomain: (name: string) =>
    request<any>(`/api/domains/${encodeURIComponent(name)}/enable`, {
      method: "POST",
    }).then(normalizeDomain),

  setDefaultDomain: (name: string) =>
    request<any>(
      `/api/domains/${encodeURIComponent(name)}/set-default`,
      { method: "POST" },
    ).then(normalizeDomain),

  /** DELETE /api/domains/{name} — admin force-delete of a disabled
   *  domain. Bypasses the `hosting.disable_purge_grace` cooling-off
   *  window. Server refuses when the domain is Active or the current
   *  default. Returns void (204 No Content). */
  deleteDomain: (name: string) =>
    request<void>(`/api/domains/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),

  // ---- Registry + per-(server, domain) ops (admin) ----

  listRegistry: () => request<ServiceInstance[]>("/api/control/registry"),

  /** POST /api/control/registry/{id}/domains/{domain}/assign — pushes
   * the assign Trust Task to the named server instance. */
  assignDomainToServer: (instanceId: string, domain: string) =>
    request<void>(
      `/api/control/registry/${encodeURIComponent(instanceId)}/domains/${encodeURIComponent(domain)}/assign`,
      { method: "POST" },
    ),

  /** Same shape — schedules a pending purge on the server side with
   * `unassigned_purge_grace` window. */
  unassignDomainFromServer: (instanceId: string, domain: string) =>
    request<void>(
      `/api/control/registry/${encodeURIComponent(instanceId)}/domains/${encodeURIComponent(domain)}/unassign`,
      { method: "POST" },
    ),

  /** Admin "Purge now" — bypasses the grace and deletes every DID on
   * the named domain on the target server immediately. */
  purgeDomainOnServer: (instanceId: string, domain: string) =>
    request<void>(
      `/api/control/registry/${encodeURIComponent(instanceId)}/domains/${encodeURIComponent(domain)}/purge`,
      { method: "POST" },
    ),

  getConfig: () => request<ControlPlaneConfig>("/api/config"),

  // Passkey auth
  passkeyEnrollStart: (token: string) =>
    request<EnrollStartResponse>("/api/auth/passkey/enroll/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    }),

  passkeyEnrollFinish: (registrationId: string, credential: any) =>
    request<TokenResponse>("/api/auth/passkey/enroll/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ registration_id: registrationId, credential }),
    }),

  passkeyLoginStart: () =>
    request<LoginStartResponse>("/api/auth/passkey/login/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),

  passkeyLoginFinish: async (authId: string, credential: any) => {
    // Generate a fresh ephemeral Ed25519 keypair for this browser
    // session and send the public multikey to the server. The server
    // binds it to the JWT session so REQUIRED-spec trust-task
    // requests (acl/grant, acl/revoke, acl/change-role) can carry
    // `eddsa-jcs-2022` Data Integrity proofs signed with the matching
    // private key. The private key stays in the CryptoKey wrapper
    // and never leaves this tab.
    const { pubkeyMultikey } = await generateSessionKeypair();
    return request<TokenResponse>("/api/auth/passkey/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        auth_id: authId,
        credential,
        session_pubkey_b58btc: pubkeyMultikey,
      }),
    });
  },

  createInvite: (did: string, role: "admin" | "owner" | "service") =>
    request<CreateInviteResponse>("/api/auth/passkey/invite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did, role }),
    }),

  listInvites: () =>
    request<InviteListResponse>("/api/auth/passkey/invites"),

  updateInvite: (
    token: string,
    updates: {
      role?: "admin" | "owner" | "service";
      expires_at?: number;
      extend_ttl?: number;
    },
  ) =>
    request<InviteListItem>(
      `/api/auth/passkey/invite/${encodeURIComponent(token)}`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(updates),
      },
    ),

  revokeInvite: (token: string) =>
    request<void>(`/api/auth/passkey/invite/${encodeURIComponent(token)}`, {
      method: "DELETE",
    }),
};

// ---------------------------------------------------------------------------
// Trust Tasks transport (v0.7.0+)
// ---------------------------------------------------------------------------

/** Trust Tasks framework Type URI prefix. */
const TT_RESPONSE_FRAGMENT = "#response";
const TT_ERROR_TYPE = "https://trusttasks.org/spec/trust-task-error/0.1";

/** Outer envelope shape produced by every `trustTask()` call. */
interface TrustTaskEnvelope<P> {
  id: string;
  type: string;
  issuer?: string;
  recipient?: string;
  issuedAt?: string;
  payload: P;
}

/** `trust-task-error/0.1` payload shape. Mirrors `trust_tasks_rs::ErrorPayload`. */
interface TrustTaskErrorPayload {
  code: string;
  message?: string;
  retryable: boolean;
  retryAfter?: string;
  details?: any;
}

/** Per-spec request-payload shapes used by the ACL surface. */
interface AclGrantPayload {
  entry: SpecAclEntry;
  reason?: string;
  ext?: Record<string, any>;
}
interface AclRevokePayload {
  subject: string;
  scopes?: string[];
  reason?: string;
  ext?: Record<string, any>;
}
interface AclChangeRolePayload {
  subject: string;
  fromRole: string;
  toRole: string;
  reason?: string;
  ext?: Record<string, any>;
}
interface AclShowPayload {
  subject: string;
  ext?: Record<string, any>;
}
interface AclListEnvelopePayload {
  role?: string;
  scope?: string;
  subjectPrefix?: string;
  pageSize?: number;
  cursor?: string;
  ext?: Record<string, any>;
}

/** Per-spec response-payload shapes. */
interface AclEntryResponsePayload {
  entry: SpecAclEntry;
  ext?: Record<string, any>;
}
interface AclShowResponsePayload {
  entry: SpecAclEntry | null;
  redactedFields?: string[];
  ext?: Record<string, any>;
}
interface AclRevokeResponsePayload {
  entry: SpecAclEntry | null;
  ext?: Record<string, any>;
}
interface AclListResponsePayload {
  entries: SpecAclEntry[];
  truncated: boolean;
  cursor?: string;
  redactedFields?: string[];
  ext?: Record<string, any>;
}

/** Wire-form AclEntry per the spec's _shared/0.1/acl-entry.schema.json. */
interface SpecAclEntry {
  subject: string;
  role: string;
  scopes?: string[];
  label?: string;
  createdAt?: string;
  createdBy?: string;
  updatedAt?: string;
  updatedBy?: string;
  expiresAt?: string;
  ext?: Record<string, any>;
}

/**
 * Set of REQUIRED-spec type URIs that MUST carry a Data Integrity
 * proof per the upstream Trust Tasks 0.1.1 framework. Proofless
 * documents on these types are rejected with `proof_required`
 * regardless of consumer policy (framework's
 * `Payload::IS_PROOF_REQUIRED` const enforced authoritatively).
 *
 * `acl/list`, `acl/show`, and `trust-task-discovery` are
 * RECOMMENDED / OPTIONAL — they're accepted proofless.
 */
const REQUIRED_PROOF_TYPES = new Set<string>([
  "https://trusttasks.org/spec/acl/grant/0.1",
  "https://trusttasks.org/spec/acl/revoke/0.1",
  "https://trusttasks.org/spec/acl/change-role/0.1",
]);

/**
 * POST `/api/trust-tasks` with a typed envelope; throw an `ApiError`
 * for `trust-task-error/0.1` responses, return the typed response
 * payload otherwise.
 *
 * REQUIRED-spec envelopes (`acl/grant`, `acl/revoke`,
 * `acl/change-role`) carry an `eddsa-jcs-2022` Data Integrity proof
 * signed by the ephemeral session keypair generated at login. The
 * proof's `verificationMethod` is the `did:key` of the
 * session pubkey; the server's `dispatch_trust_task` verifies that
 * matches the JWT-bound pubkey before the framework's verifier runs.
 *
 * `issuer` stays omitted — the bearer JWT carries the caller's DID and
 * SPEC.md §4.8.1's "transport-derived fills the absent in-band" rule
 * populates the issuer server-side. `recipient` is set explicitly whenever
 * a proof is attached: SPEC §4.8.2 (audience binding) requires it on every
 * signed envelope on a non-bearer specification (acl/grant, acl/revoke,
 * acl/change-role) so the signature is bound to *this* server and can't be
 * replayed against another verifier. The proof's `verificationMethod` ties
 * the signature to the session keypair, not the JWT subject's published DID.
 */
async function trustTask<Req, Resp>(
  typeUri: string,
  payload: Req,
): Promise<Resp> {
  const id = `urn:uuid:${cryptoRandomUuid()}`;
  const envelope: TrustTaskEnvelope<Req> = {
    id,
    type: typeUri,
    issuedAt: new Date().toISOString(),
    payload,
  };

  // REQUIRED-spec envelopes need a Data Integrity proof. The
  // resolution order:
  //   1. In-memory keypair from this tab (login or earlier restore).
  //   2. IndexedDB restore — survives page reloads while the JWT is
  //      still cached in localStorage, so the user doesn't have to
  //      re-login every time they refresh the admin page.
  //   3. Fall through to generate a fresh keypair (will fail server-
  //      side with `proof_invalid` because the new pubkey isn't bound
  //      to the JWT) — the failure prompts the user to log in again.
  if (REQUIRED_PROOF_TYPES.has(typeUri)) {
    // §4.8.2 audience binding: bind the signature to *this* server before
    // signing. Without `recipient`, the framework rejects with
    // `malformed_request` ("proof present with no in-band recipient on a
    // non-bearer specification").
    const info = await getServerInfo();
    if (!info.server_did) {
      throw new ApiError(
        500,
        "server_did is not configured — signed trust tasks cannot be sent",
      );
    }
    envelope.recipient = info.server_did;

    // Two signing paths, picked by which login flow produced the JWT:
    //
    // (1) Wallet login → the VTI browser extension's holder did:peer is the
    //     signing authority. The wallet adds the eddsa-jcs-2022 proof
    //     server-side from the page's perspective (it runs in the
    //     extension's offscreen doc with the private key). The server
    //     resolves the did:peer to verify; the dispatch_trust_task pre-check
    //     enforces that the proof's DID == JWT.sub.
    //
    // (2) Passkey login → ephemeral session keypair (generated at login,
    //     pubkey bound to the JWT by the server). dispatch_trust_task
    //     enforces that the proof's verificationMethod is exactly the
    //     JWT-bound `did:key:{pk}#{pk}`.
    const method = getAuthMethod();
    if (method === "wallet") {
      const wallet = (
        typeof window !== "undefined"
          ? (window as unknown as { vtaWallet?: { signTrustTask: (p: { envelope: Record<string, unknown> }) => Promise<{ signedEnvelope: Record<string, unknown> }> } }).vtaWallet
          : undefined
      );
      if (!wallet?.signTrustTask) {
        throw new ApiError(
          401,
          "Wallet-authenticated session but the VTA Wallet extension is not available to sign. Re-install the extension or log out + back in with passkey.",
        );
      }
      const signed = await wallet.signTrustTask({
        envelope: envelope as unknown as Record<string, unknown>,
      });
      // Replace our envelope with the signed one (the wallet may have
      // copied + added `proof`; the rest of the fields must be byte-
      // identical so the server's JCS hash matches).
      Object.assign(envelope as unknown as Record<string, unknown>, signed.signedEnvelope);
    } else {
      if (!hasSessionKeypair()) {
        await restoreSessionKeypair();
      }
      if (!hasSessionKeypair()) {
        await generateSessionKeypair();
      }
      await signEnvelope(envelope as unknown as Record<string, unknown>);
    }
  }

  const respDoc = await request<TrustTaskEnvelope<Resp | TrustTaskErrorPayload>>(
    "/api/trust-tasks",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
    },
  );

  // Successful response carries `type: <request-type>#response`. An
  // error response carries `type: <trust-task-error/0.1>`. We
  // discriminate on the response envelope's `type` to surface the
  // right shape to the caller.
  if (respDoc.type === TT_ERROR_TYPE) {
    const err = respDoc.payload as TrustTaskErrorPayload;
    throw new ApiError(
      422, // surface as application-layer; the HTTP status carried the same signal
      err.message ?? err.code ?? "trust task rejected",
    );
  }
  if (!respDoc.type.endsWith(TT_RESPONSE_FRAGMENT)) {
    throw new ApiError(
      500,
      `unexpected trust-task response type: ${respDoc.type}`,
    );
  }
  return respDoc.payload as Resp;
}

/** Browser-safe UUIDv4. Falls back to a polyfill where crypto.randomUUID
 * isn't available (e.g. iOS Safari < 15.4). */
function cryptoRandomUuid(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // RFC 4122 v4 polyfill via getRandomValues.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex
    .slice(6, 8)
    .join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}

/** Project a spec-wire `SpecAclEntry` into the existing `AclEntry`
 * shape the UI screens already render. The wire form carries webvh
 * fields under `ext.vnd.affinidi.webvh.*`; the UI reads them off
 * the top-level `AclEntry` for backwards-compat with v0.7 code. */
function specEntryToLocal(spec: SpecAclEntry): AclEntry {
  const role = spec.role as "admin" | "owner" | "service";
  const webvh: any = spec.ext?.["vnd.affinidi.webvh"] ?? {};
  const quota: any = webvh.quota ?? {};
  const createdAt = spec.createdAt
    ? Math.floor(new Date(spec.createdAt).getTime() / 1000)
    : 0;
  return {
    did: spec.subject,
    role,
    label: spec.label ?? null,
    created_at: createdAt,
    max_total_size:
      typeof quota.maxTotalSize === "number" ? quota.maxTotalSize : null,
    max_did_count:
      typeof quota.maxDidCount === "number" ? quota.maxDidCount : null,
    domains: (webvh.domains as DomainScope | undefined) ?? { kind: "all" },
  };
}
