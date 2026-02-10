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
}

export interface CreateDidResponse {
  mnemonic: string;
  didUrl: string;
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
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<HealthResponse>("/health"),

  listDids: () => request<DidRecord[]>("/dids"),

  createDid: () =>
    request<CreateDidResponse>("/dids", { method: "POST" }),

  uploadDid: (mnemonic: string, body: string) =>
    request<void>(`/dids/${mnemonic}`, {
      method: "PUT",
      headers: { "Content-Type": "text/plain" },
      body,
    }),

  uploadWitness: (mnemonic: string, body: string) =>
    request<void>(`/dids/${mnemonic}/witness`, {
      method: "PUT",
      headers: { "Content-Type": "text/plain" },
      body,
    }),

  deleteDid: (mnemonic: string) =>
    request<void>(`/dids/${mnemonic}`, { method: "DELETE" }),

  getStats: (mnemonic: string) =>
    request<DidStats>(`/stats/${mnemonic}`),

  listAcl: () => request<AclListResponse>("/acl"),

  createAcl: (did: string, role: "admin" | "owner", label?: string) =>
    request<AclEntry>("/acl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did, role, label }),
    }),

  deleteAcl: (did: string) =>
    request<void>(`/acl/${encodeURIComponent(did)}`, { method: "DELETE" }),

  // Passkey auth
  passkeyEnrollStart: (token: string) =>
    request<EnrollStartResponse>("/auth/passkey/enroll/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    }),

  passkeyEnrollFinish: (registrationId: string, credential: any) =>
    request<TokenResponse>("/auth/passkey/enroll/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ registration_id: registrationId, credential }),
    }),

  passkeyLoginStart: () =>
    request<LoginStartResponse>("/auth/passkey/login/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),

  passkeyLoginFinish: (authId: string, credential: any) =>
    request<TokenResponse>("/auth/passkey/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auth_id: authId, credential }),
    }),
};
