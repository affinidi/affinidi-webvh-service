/** Plain HTTP to the control plane: the error type, and the one helper the
 *  remaining non-Trust-Task routes (health, passkey enrolment, the REST token
 *  refresh) and the Trust Task binding itself go through. */

import { clearToken, getToken, renewIfNeeded } from "./session";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /**
     * The raw response body, when there was one.
     *
     * Kept because a Trust-Task rejection arrives *as a document* at a non-2xx
     * status (`status_for_code` maps `permissionDenied` → 403, `taskFailed` →
     * 422, …). Throwing on the status alone discards that document, and with it
     * the `code` / `retryable` / `retryAfter` members the §8.4 retry policy is
     * written against — leaving the caller to match on message text, which is
     * the thing that policy exists to avoid.
     */
    public body?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface RequestOptions extends RequestInit {
  /** Send no bearer token, whatever the session holds — for a public read. */
  anonymous?: boolean;
}

export async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  // Renew ahead of expiry, so an operator who is using the console is not
  // signed out mid-task. Skipped for the renewal call itself, which would
  // otherwise recurse.
  const { anonymous = false, ...init } = options;
  if (!anonymous && path !== "/api/auth/refresh") {
    await renewIfNeeded();
  }
  const token = anonymous ? null : getToken();
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...init, headers });

  if (!res.ok) {
    // A 401 on a request that carried the session means the session is gone.
    // One that carried none says nothing about it.
    if (res.status === 401 && token) {
      clearToken();
      window.dispatchEvent(new Event("webvh:unauthorized"));
    }
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text, text);
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
