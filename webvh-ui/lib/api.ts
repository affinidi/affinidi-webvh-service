/** Typed API client for the webvh-server REST API. */

export interface HealthResponse {
  status: string;
  version: string;
}

export interface DidRecord {
  mnemonic: string;
  createdAt: number;
  updatedAt: number;
  versionCount: number;
  didId: string | null;
  totalResolves: number;
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
  deactivated: boolean;
  ttl: number | null;
}

export interface DidDetailResponse {
  mnemonic: string;
  createdAt: number;
  updatedAt: number;
  versionCount: number;
  didId: string | null;
  owner: string;
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
  didUrl: string;
}

export interface CheckNameResponse {
  available: boolean;
  path: string;
}

export interface AclEntry {
  did: string;
  role: "admin" | "owner";
  label: string | null;
  created_at: number;
}

export interface AclListResponse {
  entries: AclEntry[];
}

export interface DidStats {
  total_resolves: number;
  total_updates: number;
  last_resolved_at: number | null;
  last_updated_at: number | null;
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

  return res.json() as Promise<T>;
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

  createDid: (path?: string) =>
    request<CreateDidResponse>("/api/dids", {
      method: "POST",
      ...(path
        ? {
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path }),
          }
        : {}),
    }),

  checkName: (path: string) =>
    request<CheckNameResponse>("/api/dids/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
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

  getStats: (mnemonic: string) =>
    request<DidStats>(`/api/stats/${mnemonic}`),

  getServerStats: () => request<ServerStats>("/api/stats"),

  getServerTimeseries: (range: TimeRange = "24h") =>
    request<TimeSeriesPoint[]>(`/api/timeseries?range=${range}`),

  getDidTimeseries: (mnemonic: string, range: TimeRange = "24h") =>
    request<TimeSeriesPoint[]>(`/api/timeseries/${mnemonic}?range=${range}`),

  listAcl: () => request<AclListResponse>("/api/acl"),

  createAcl: (did: string, role: "admin" | "owner", label?: string) =>
    request<AclEntry>("/api/acl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did, role, label }),
    }),

  deleteAcl: (did: string) =>
    request<void>(`/api/acl/${encodeURIComponent(did)}`, { method: "DELETE" }),

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
};
