/** VTI browser-extension wallet bridge.
 *
 * On web, the wallet extension injects `window.vtaWallet` into pages matching
 * its `host_permissions`. This module is the UI-side feature-detect + a thin
 * wrapper that asks the wallet to log into THIS did-hosting server.
 *
 * The wallet's SIOPv2 path round-trips against `${baseUrl}/auth/challenge` and
 * `${baseUrl}/auth/` — the exact endpoints did-hosting-control exposes — and
 * returns a server-issued bearer token. That token is fed into
 * `AuthProvider.login(...)` identically to the passkey path; both yield the
 * same JWT shape, so nothing else in the UI needs to know which path was taken.
 *
 * Native (iOS / Android) builds never see `window.vtaWallet`; the helper
 * degrades gracefully via `isWalletAvailable()`.
 */

import { Platform } from "react-native";

/** A subset of the wallet provider's interface — just the SIOPv2 login.
 *  Declaring it inline keeps did-hosting-ui from depending on the extension
 *  package. The full interface lives in `@pnm/extension/provider.ts`. */
interface VtaWalletLoginParams {
  rpDid: string;
  baseUrl: string;
}
export interface VtaWalletLoginResult {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  holderDid: string;
}
interface VtaWalletSignTrustTaskParams {
  envelope: Record<string, unknown>;
}
interface VtaWalletSignTrustTaskResult {
  signedEnvelope: Record<string, unknown>;
  holderDid: string;
}

/** Subset of `VaultEntryView` we read from the wallet's page-world
 *  vaultList API — only the fields the demo needs. */
export interface ProxyVaultEntry {
  id: string;
  label: string;
  contextId: string;
  secretKind: string;
  principalDid?: string;
  targets: Array<{ kind: string; [k: string]: unknown }>;
  lastUsedAt?: string;
}
interface VaultListWireResult {
  entries: ProxyVaultEntry[];
  truncated: boolean;
}
interface ProxyLoginWireResult {
  sessionBlob: {
    sessionId: string;
    expiresAt: string;
    headers?: Array<{ name: string; value: string }>;
    cookies?: unknown[];
    bindOrigin?: string;
  };
  sessionId: string;
  expiresAt: string;
}

interface VtaWalletProvider {
  login(params: VtaWalletLoginParams): Promise<VtaWalletLoginResult>;
  /** Sign a Trust-Task envelope with the wallet's holder did:peer #key-2.
   *  The caller sets `recipient` (audience) on the envelope before calling;
   *  the wallet adds an `eddsa-jcs-2022` Data Integrity proof and returns the
   *  envelope. Server verifies by resolving the did:peer. */
  signTrustTask?(
    params: VtaWalletSignTrustTaskParams,
  ): Promise<VtaWalletSignTrustTaskResult>;
  /** Enumerate vault entries pinned to a given DID / secret kind. */
  vaultList?(params: {
    targetDid?: string;
    targetOriginPrefix?: string;
    secretKind?: string;
  }): Promise<VaultListWireResult>;
  /** VTA-proxied login (vault/proxy-login/0.1) — VTA mints a SIOP id_token
   *  on behalf of a did-self-issued vault entry; long-term key never leaves
   *  the VTA. */
  proxyLogin?(params: {
    entryId: string;
    nonce?: string;
    target?: { kind: string; [k: string]: unknown };
    ttlSecondsHint?: number;
  }): Promise<ProxyLoginWireResult>;
}
declare global {
  interface Window {
    vtaWallet?: VtaWalletProvider;
  }
}

/** True iff this is a web build AND the wallet extension has injected its
 *  provider into the page. False on iOS/Android or when the extension is
 *  missing — callers should hide the wallet button + show an install hint. */
export function isWalletAvailable(): boolean {
  return (
    Platform.OS === "web" &&
    typeof window !== "undefined" &&
    typeof window.vtaWallet?.login === "function"
  );
}

/** The RP DID the wallet signs the SIOPv2 `id_token` for. Reads
 *  `EXPO_PUBLIC_RP_DID` at build time; defaults to the demo VTA so a
 *  fresh checkout works without env-var plumbing. Operators with their own
 *  VTA set the env var. */
export function getRpDid(): string {
  return (
    process.env.EXPO_PUBLIC_RP_DID ??
    "did:webvh:QmUcydmZKWsAUcuAGzyQRjXnSvnMdSRF1YM7gyhugYGS9s:webvh.storm.ws"
  );
}

/** API base for the wallet's SIOPv2 round-trip. The UI is served same-origin
 *  with the did-hosting-control API at `/api`, so the default resolves the
 *  wallet's `${baseUrl}/auth/challenge` to the right endpoint without
 *  configuration. Override with `EXPO_PUBLIC_API_BASE` if the API is on a
 *  separate origin. */
export function getApiBase(): string {
  if (process.env.EXPO_PUBLIC_API_BASE) return process.env.EXPO_PUBLIC_API_BASE;
  return (typeof window !== "undefined" ? window.location.origin : "") + "/api";
}

/** Trigger the wallet's SIOPv2 login. Resolves to the result containing the
 *  server-issued access token (suitable for `AuthProvider.login`); rejects
 *  if the wallet isn't available, the user denies the consent prompt, or the
 *  server rejects the `id_token`. */
export async function loginWithWallet(): Promise<VtaWalletLoginResult> {
  if (!isWalletAvailable()) {
    throw new Error(
      "VTA wallet extension is not installed (or this isn't running in a web browser).",
    );
  }
  return window.vtaWallet!.login({
    rpDid: getRpDid(),
    baseUrl: getApiBase(),
  });
}

/** True iff the page-world wallet exposes the proxy-login + vault-list
 *  APIs (M2B.3 / M2B.4 plugin). Older wallet builds advertise only the
 *  classic `login()` — the demo's wallet-proxy button is hidden when
 *  this is false. */
export function isWalletProxyAvailable(): boolean {
  return (
    isWalletAvailable() &&
    typeof window.vtaWallet?.proxyLogin === "function" &&
    typeof window.vtaWallet?.vaultList === "function"
  );
}

// ─── M2B.4 VTA-proxied login (vault/proxy-login/0.1) ──────────────────
//
// Three round-trips:
//   1. Ask the wallet for did-self-issued entries pinned to this RP's DID
//      via `vtaWallet.vaultList({ targetDid, secretKind })`.
//   2. POST /api/auth/challenge with `did: principalDid` to get a
//      challenge nonce bound to that principal.
//   3. Ask the wallet to mint a SIOP id_token for the chosen entry with
//      the challenge as nonce via `vtaWallet.proxyLogin({...})`.
//   4. POST /api/auth/ with `{ id_token, session_id }` — the server
//      verifies and returns a TokenResponse.
//
// Each step is timed and captured into a `ProxyLoginViz` value so the
// login UI can render a sequence diagram + decoded id_token after the
// flow completes. The visualization is the M2B.4 demo deliverable;
// auth still works without rendering it.

const AUTH_AUTHENTICATE_TYPE_URI =
  "https://trusttasks.org/spec/auth/authenticate/0.1";

/** One step in the visualisation. Captured with timing so the UI can
 *  render relative durations. */
export interface ProxyLoginVizStep {
  label: string;
  description: string;
  durationMs: number;
  detail?: Record<string, unknown>;
}

/** Decoded JWT header + payload, parsed from the SIOP id_token after
 *  the proxy-login round-trip. Surfaced in the UI so the demo can show
 *  the user what the VTA actually minted. */
export interface DecodedIdToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Compact JWS (header.payload.signature). */
  compact: string;
}

export interface ProxyLoginViz {
  rpDid: string;
  apiBase: string;
  chosenEntry: {
    id: string;
    label: string;
    contextId: string;
    principalDid: string;
  };
  steps: ProxyLoginVizStep[];
  idToken?: DecodedIdToken;
  sessionBlob?: {
    sessionId: string;
    expiresAt: string;
    bindOrigin?: string;
    headerCount: number;
    cookieCount: number;
  };
  totalMs: number;
}

export interface ProxyLoginOutcome {
  result: VtaWalletLoginResult;
  viz: ProxyLoginViz;
}

/** Strip "Bearer " prefix from an Authorization header value and return
 *  the trimmed token. Returns null if the value doesn't look like a
 *  bearer header. */
function extractBearer(headerValue: string): string | null {
  const m = /^\s*Bearer\s+(.+)\s*$/i.exec(headerValue);
  return m && m[1] ? m[1] : null;
}

/** Base64url-decode a JWS segment to a JSON object. JWT compact form
 *  segments are URL-safe base64 without padding, so we restore padding
 *  before decoding. */
function decodeJwtSegment(seg: string): Record<string, unknown> {
  const pad = "=".repeat((4 - (seg.length % 4)) % 4);
  const b64 = (seg + pad).replace(/-/g, "+").replace(/_/g, "/");
  const json = typeof atob === "function"
    ? atob(b64)
    : Buffer.from(b64, "base64").toString("utf8");
  return JSON.parse(json) as Record<string, unknown>;
}

/** Parse a compact JWS into its header + payload (signature ignored —
 *  the server already verified it before returning the access token,
 *  and this helper is for display only). Throws on malformed input. */
export function decodeIdToken(compact: string): DecodedIdToken {
  const parts = compact.split(".");
  if (parts.length !== 3) {
    throw new Error(`id_token is not a compact JWS (got ${parts.length} parts)`);
  }
  return {
    header: decodeJwtSegment(parts[0]!),
    payload: decodeJwtSegment(parts[1]!),
    compact,
  };
}

/** Enumerate proxy-login candidates for this RP via the wallet's
 *  page-world `vaultList`. Filters to `did-self-issued` entries pinned
 *  to the RP's DID. Used by the login UI to populate the entry picker. */
export async function listProxyCandidates(): Promise<ProxyVaultEntry[]> {
  if (!isWalletProxyAvailable()) {
    throw new Error(
      "VTI Wallet doesn't expose proxy-login APIs (extension may be out of date).",
    );
  }
  const rpDid = getRpDid();
  const wire = await window.vtaWallet!.vaultList!({
    targetDid: rpDid,
    secretKind: "did-self-issued",
  });
  return wire.entries.filter((e) => Boolean(e.principalDid));
}

/** Run the full VTA-proxied login flow against a chosen entry. Returns
 *  both the auth result (suitable for `AuthProvider.login`) and a
 *  visualization payload describing what happened, for the demo's
 *  walkthrough UI. */
export async function loginWithWalletProxy(
  entry: ProxyVaultEntry,
): Promise<ProxyLoginOutcome> {
  if (!isWalletProxyAvailable()) {
    throw new Error(
      "VTI Wallet doesn't expose proxy-login APIs (extension may be out of date).",
    );
  }
  if (!entry.principalDid) {
    throw new Error(
      "Chosen entry has no principalDid — only did-self-issued entries are supported for SIOP proxy login.",
    );
  }
  const rpDid = getRpDid();
  const apiBase = getApiBase().replace(/\/+$/, "");
  const steps: ProxyLoginVizStep[] = [];
  const t0 = performance.now();

  // ─── Step 1: fetch a challenge keyed on the entry's principal DID.
  const tCh = performance.now();
  const chRes = await fetch(`${apiBase}/auth/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ did: entry.principalDid }),
  });
  if (!chRes.ok) {
    const text = await chRes.text();
    throw new Error(`/auth/challenge failed (${chRes.status}): ${text}`);
  }
  const chJson = (await chRes.json()) as {
    challenge: string;
    session_id: string;
    expires_at?: number;
  };
  steps.push({
    label: "1. Fetch challenge",
    description: `Page POSTs /auth/challenge with the entry's principal DID. The RP returns a one-shot nonce bound to that DID.`,
    durationMs: Math.round(performance.now() - tCh),
    detail: {
      url: `${apiBase}/auth/challenge`,
      requestBody: { did: entry.principalDid },
      response: chJson,
    },
  });

  // ─── Step 2: ask the wallet (via VTA) to mint a SIOP id_token with
  //            this challenge as nonce. The long-term key never leaves
  //            the VTA — wallet only sees the resulting SessionBlob.
  const tPl = performance.now();
  const pl = await window.vtaWallet!.proxyLogin!({
    entryId: entry.id,
    nonce: chJson.challenge,
    target: { kind: "did", did: rpDid },
  });
  const authHeader = pl.sessionBlob.headers?.find(
    (h) => h.name.toLowerCase() === "authorization",
  );
  const idTokenCompact = authHeader ? extractBearer(authHeader.value) : null;
  if (!idTokenCompact) {
    throw new Error(
      "vault/proxy-login: SessionBlob has no Authorization header — did-self-issued driver expected to emit one.",
    );
  }
  const decoded = decodeIdToken(idTokenCompact);
  steps.push({
    label: "2. VTA mints SIOP id_token",
    description: `Wallet asks the VTA via vault/proxy-login/0.1 to mint an id_token signed by the entry's DID, embedding the RP's challenge as nonce. The wallet receives a SessionBlob with the id_token in an Authorization header.`,
    durationMs: Math.round(performance.now() - tPl),
    detail: {
      vaultEntryId: entry.id,
      principalDid: entry.principalDid,
      sessionId: pl.sessionId,
      expiresAt: pl.expiresAt,
      idTokenClaims: decoded.payload,
    },
  });

  // ─── Step 3: post the id_token to /auth/. The server verifies the
  //            signature against the entry's DID + checks nonce + aud
  //            + iat/exp window, then issues access tokens.
  const tAuth = performance.now();
  const authEnv = {
    type: AUTH_AUTHENTICATE_TYPE_URI,
    payload: {
      id_token: idTokenCompact,
      session_id: chJson.session_id,
    },
  };
  const authRes = await fetch(`${apiBase}/auth/`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(authEnv),
  });
  if (!authRes.ok) {
    const text = await authRes.text();
    throw new Error(`/auth/ failed (${authRes.status}): ${text}`);
  }
  const tokenResp = (await authRes.json()) as {
    session_id: string;
    access_token: string;
    refresh_token: string;
    refresh_expires_at?: number;
  };
  steps.push({
    label: "3. Server verifies + issues bearer",
    description: `Server resolves the entry's DID, verifies the id_token signature, checks the nonce matches the challenge it issued in step 1, and issues a bearer access token bound to the principal DID.`,
    durationMs: Math.round(performance.now() - tAuth),
    detail: {
      url: `${apiBase}/auth/`,
      requestBody: authEnv,
      response: {
        session_id: tokenResp.session_id,
        access_token: tokenResp.access_token
          ? `${tokenResp.access_token.slice(0, 12)}…(redacted)`
          : "",
        refresh_expires_at: tokenResp.refresh_expires_at ?? null,
      },
    },
  });

  const totalMs = Math.round(performance.now() - t0);

  return {
    result: {
      accessToken: tokenResp.access_token,
      refreshToken: tokenResp.refresh_token,
      sessionId: tokenResp.session_id,
      holderDid: entry.principalDid,
    },
    viz: {
      rpDid,
      apiBase,
      chosenEntry: {
        id: entry.id,
        label: entry.label,
        contextId: entry.contextId,
        principalDid: entry.principalDid,
      },
      steps,
      idToken: decoded,
      sessionBlob: {
        sessionId: pl.sessionBlob.sessionId,
        expiresAt: pl.sessionBlob.expiresAt,
        ...(pl.sessionBlob.bindOrigin
          ? { bindOrigin: pl.sessionBlob.bindOrigin }
          : {}),
        headerCount: pl.sessionBlob.headers?.length ?? 0,
        cookieCount: pl.sessionBlob.cookies?.length ?? 0,
      },
      totalMs,
    },
  };
}
