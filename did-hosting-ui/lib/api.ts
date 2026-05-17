/** Typed API client for the did-hosting-control REST API. */

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

/** Server-side `DomainEntry` (`KS_DOMAINS`). camelCase wire shape. */
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
}

export interface DomainListResponse {
  domains: DomainEntry[];
  /** Currently-elected system default; may be null on a fresh install. */
  default: string | null;
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

export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    // ignore
  }
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

export const api = {
  health: () => request<HealthResponse>("/api/health"),

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

  listAcl: () => request<AclListResponse>("/api/acl"),

  createAcl: (
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
  ) =>
    request<AclEntry>("/api/acl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did,
        role,
        label: opts?.label,
        max_total_size: opts?.maxTotalSize,
        max_did_count: opts?.maxDidCount,
        domains: opts?.domains,
      }),
    }),

  updateAcl: (
    did: string,
    updates: {
      role?: "admin" | "owner" | "service";
      label?: string | null;
      maxTotalSize?: number | null;
      maxDidCount?: number | null;
      domains?: DomainScope;
    },
  ) =>
    request<AclEntry>(`/api/acl/${encodeURIComponent(did)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        role: updates.role,
        label: updates.label,
        max_total_size: updates.maxTotalSize,
        max_did_count: updates.maxDidCount,
        domains: updates.domains,
      }),
    }),

  deleteAcl: (did: string) =>
    request<void>(`/api/acl/${encodeURIComponent(did)}`, { method: "DELETE" }),

  // ---- Multi-domain (v0.7) ----

  /** GET /api/domains — Admin only. */
  listDomains: () => request<DomainListResponse>("/api/domains"),

  /** GET /api/me/domains — caller-scoped subset; returns the caller's
   * default in the `default` field (falls back to the system default
   * when the caller's scope is `All` / `Allowed` without a default). */
  listMyDomains: () => request<DomainListResponse>("/api/me/domains"),

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
    request<DomainEntry>("/api/domains", {
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
    }),

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
    request<DomainEntry>(`/api/domains/${encodeURIComponent(name)}`, {
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
    }),

  disableDomain: (name: string) =>
    request<DomainEntry>(`/api/domains/${encodeURIComponent(name)}/disable`, {
      method: "POST",
    }),

  enableDomain: (name: string) =>
    request<DomainEntry>(`/api/domains/${encodeURIComponent(name)}/enable`, {
      method: "POST",
    }),

  setDefaultDomain: (name: string) =>
    request<DomainEntry>(
      `/api/domains/${encodeURIComponent(name)}/set-default`,
      { method: "POST" },
    ),

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

  passkeyLoginFinish: (authId: string, credential: any) =>
    request<TokenResponse>("/api/auth/passkey/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auth_id: authId, credential }),
    }),

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
