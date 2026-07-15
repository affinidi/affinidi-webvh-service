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

import { api } from "./api";

/** A subset of the wallet provider's interface — just the SIOPv2 login.
 *  Declaring it inline keeps did-hosting-ui from depending on the extension
 *  package. The full interface lives in
 *  `@openvtc/pnm-extension/provider.ts`. */
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

/** Canonical `secretKind` wire values — camelCase, mirroring
 *  `vault/_shared/0.2/vault-entry.schema.json#/$defs/SecretKind`. The
 *  maintainer schema-validates this enum before dispatch, so a
 *  kebab-case value is a payload rejection, not a no-op filter. Keep
 *  this the single source of truth for outbound `secretKind` filters. */
export type SecretKind =
  | "password"
  | "passkey"
  | "oauthTokens"
  | "didSelfIssued"
  | "didcommPeer"
  | "bearerToken"
  | "sshKey"
  | "custom";

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
  /** Propose a Trust Task for the user's VTA to execute.
   *
   *  The generic relay. We supply a type URI and a payload and nothing else:
   *  the extension mints the envelope inside its own trust boundary and stamps
   *  the origin the browser attested. We never author an envelope for the
   *  wallet to counter-sign — a wallet that signed what we wrote would be
   *  vouching for a document it never checked, and we are the least trusted
   *  party in this picture.
   *
   *  Resolves with whatever the VTA replied, INCLUDING a refusal. */
  requestTask?(params: {
    type: string;
    payload: Record<string, unknown>;
  }): Promise<Record<string, unknown>>;
  /** Enumerate vault entries pinned to a given DID / secret kind. */
  vaultList?(params: {
    targetDid?: string;
    targetOriginPrefix?: string;
    secretKind?: SecretKind;
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

/** The RP DID the wallet signs the SIOPv2 `id_token` for.
 *
 *  Sourced at runtime from THIS control plane's own DID via
 *  `GET /api/server-info` (`server_did`). That is the exact value the
 *  server compares the id_token `aud` against in `auth.rs`, so the wallet
 *  and the verifier can never disagree — and a single prebuilt UI bundle
 *  works against any deployment without baking a DID in at build time.
 *  `api.serverInfo()` caches per-tab, so this is one network round-trip.
 *
 *  `EXPO_PUBLIC_RP_DID` remains an explicit override for the unusual case
 *  where the wallet must target a DID other than this deployment's
 *  control-plane DID; leave it unset to track the control plane. */
export async function getRpDid(): Promise<string> {
  const override = process.env.EXPO_PUBLIC_RP_DID;
  if (override) return override;
  const info = await api.serverInfo();
  if (!info.server_did) {
    throw new Error(
      "This deployment has no server_did configured (GET /api/server-info returned null), " +
        "so the wallet can't determine the RP DID for SIOP login. Set `server_did` in the " +
        "control-plane config (or the CONTROL_SERVER_DID env var).",
    );
  }
  return info.server_did;
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
    rpDid: await getRpDid(),
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
  // `atob` is present in all our target runtimes (browser + Hermes); the
  // Node `Buffer` path is a defensive fallback. Reach it through a typed
  // `globalThis` guard rather than the ambient Node global, which isn't
  // resolvable under this project's bundler/react-native type resolution
  // (and we deliberately don't pull `@types/node` into a React Native app).
  const json =
    typeof atob === "function"
      ? atob(b64)
      : (
          globalThis as unknown as {
            Buffer: { from(s: string, enc: string): { toString(enc: string): string } };
          }
        ).Buffer.from(b64, "base64").toString("utf8");
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
  const rpDid = await getRpDid();
  const wire = await window.vtaWallet!.vaultList!({
    targetDid: rpDid,
    secretKind: "didSelfIssued",
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
  const rpDid = await getRpDid();
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
  // Wire-format asymmetry in did-hosting-control:
  //   - ChallengeResponse uses camelCase (`#[serde(rename_all =
  //     "camelCase")]` in did-hosting-common's types.rs) →
  //     `{ challenge, sessionId, expiresAt }` on the wire.
  //   - AuthenticatePayload has NO rename_all → still snake_case
  //     (`{ id_token, session_id, ... }`).
  // The original draft of this file read `session_id` from both,
  // which left the auth POST with `session_id: undefined` and the
  // server complaining "missing field `session_id`". Read camelCase
  // here; emit snake_case in step 3.
  const chJson = (await chRes.json()) as {
    challenge: string;
    sessionId: string;
    expiresAt?: string;
  };
  if (!chJson.sessionId || !chJson.challenge) {
    throw new Error(
      `/auth/challenge: malformed response (missing sessionId or challenge): ${JSON.stringify(chJson)}`,
    );
  }
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
      // Server expects snake_case here (no rename_all on
      // AuthenticatePayload). Read from camelCase sessionId on
      // chJson — that's the wire shape the challenge endpoint
      // emits.
      session_id: chJson.sessionId,
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
  // /auth/ returns the canonical AuthenticateResponse: `{ session,
  // tokens }`. Both nested structs (Session, TokenBundle) have
  // `#[serde(rename_all = "camelCase")]` upstream in did-hosting-
  // common's types.rs, so the wire shape is fully camelCase. The
  // earlier draft of this file parsed the response with a flat
  // snake_case shape (`{ access_token, refresh_token, session_id }`)
  // — every field came out `undefined`, the wallet stored
  // `undefined` as the token, and the home page bounced back to
  // login. Mirror the canonical shape here.
  const tokenResp = (await authRes.json()) as {
    session: { id: string; subject: string; issuedAt: string; expiresAt: string };
    tokens: {
      accessToken: string;
      refreshToken?: string;
      tokenType: string;
      expiresIn: number;
      refreshExpiresIn?: number;
    };
  };
  if (!tokenResp.tokens?.accessToken) {
    throw new Error(
      `/auth/: missing tokens.accessToken in response — got ${JSON.stringify(tokenResp).slice(0, 200)}`,
    );
  }
  steps.push({
    label: "3. Server verifies + issues bearer",
    description: `Server resolves the entry's DID, verifies the id_token signature, checks the nonce matches the challenge it issued in step 1, and issues a bearer access token bound to the principal DID.`,
    durationMs: Math.round(performance.now() - tAuth),
    detail: {
      url: `${apiBase}/auth/`,
      requestBody: authEnv,
      response: {
        sessionId: tokenResp.session.id,
        sessionSubject: tokenResp.session.subject,
        accessToken: `${tokenResp.tokens.accessToken.slice(0, 12)}…(redacted)`,
        tokenType: tokenResp.tokens.tokenType,
        expiresIn: tokenResp.tokens.expiresIn,
      },
    },
  });

  const totalMs = Math.round(performance.now() - t0);

  return {
    result: {
      accessToken: tokenResp.tokens.accessToken,
      refreshToken: tokenResp.tokens.refreshToken ?? "",
      sessionId: tokenResp.session.id,
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


// ─── Delegated task execution (requestTask) ───────────────────────────
//
// The point of this path: we do not hold the DID's update key and we never
// will. We propose an edit; the user's VTA decides whether to make it, dry-runs
// its own update handler to work out what the edit would actually do, and — if
// the user's policy says so — asks a human on another device to approve it.
//
// This is why the hosting service needs no changes at all. It already verifies
// the proof chain on whatever log it is handed; it never cared who submitted.
// The trust boundary was drawn in the right place before any of this existed.

/** True iff the wallet exposes the generic task relay. */
export function isWalletTaskRelayAvailable(): boolean {
  return isWalletAvailable() && typeof window.vtaWallet?.requestTask === "function";
}

// The `vta/` segment is not decoration. The VTA dispatches on this exact string
// (`vta-sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0`); without it the task is
// unrecognised, so there is no class, no planner and no consent request — the
// request simply fails as an unknown method, which looks like a transport
// problem rather than the typo it is.
export const WEBVH_DIDS_UPDATE_1_0 =
  "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";

/** The VTA needs a human to approve this before it will run it. */
export interface TaskConsentRequired {
  kind: "consentRequired";
  /** The class the VTA derived from the compiled handler. `destructive` means the
   *  approving device will require the user to TYPE the code rather than tap
   *  approve — so we must tell them a match is expected, not merely show it. */
  sideEffects?: string;
  /**
   * The salted digest of the exact payload awaiting approval.
   *
   * We display a prefix of this, and the approver's device displays the same
   * prefix. The user compares them. That comparison is the only check in the
   * whole design that survives a compromised consent surface — every other
   * check assumes an honest device, and a device that is lying to the user can
   * satisfy all of them. Only moving the comparison into the user's head,
   * across two screens neither of which the attacker controls both of, catches
   * it.
   *
   * Which is also why this must never be reduced to a "waiting for approval…"
   * spinner. The code is the ceremony.
   */
  payloadDigest: string;
  approverSet: string;
  minApprovals: number;
}

export interface TaskAccepted {
  kind: "accepted";
  result: Record<string, unknown>;
}

export type RequestTaskOutcome = TaskAccepted | TaskConsentRequired;

/** How much of the digest a human is asked to compare. */
export const DIGEST_PREFIX_LEN = 6;

export function digestPrefix(payloadDigest: string): string {
  return payloadDigest.slice(0, DIGEST_PREFIX_LEN);
}

/**
 * Ask the user's VTA to update a DID document.
 *
 * We send the document we want and the version we based it on. That
 * `expectedVersionId` is not a formality: a human in the approval loop makes the
 * window minutes wide, so the log really can move underneath us, and without it
 * the VTA would happily apply our edit on top of someone else's — a lost update
 * that every signature in the chain would still verify.
 */
export async function requestDidUpdate(args: {
  did: string;
  document: Record<string, unknown>;
  expectedVersionId?: string;
}): Promise<RequestTaskOutcome> {
  const wallet = window.vtaWallet;
  if (!wallet?.requestTask) {
    throw new Error("This wallet does not support delegated task execution.");
  }

  // The wallet returns a discriminated outcome: a `requireConsent` refusal is a
  // result, not an error. See `readOutcome`.
  const reply = (await wallet.requestTask({
    type: WEBVH_DIDS_UPDATE_1_0,
    payload: {
      did: args.did,
      document: args.document,
      ...(args.expectedVersionId ? { expectedVersionId: args.expectedVersionId } : {}),
    },
  })) as Record<string, unknown>;

  return readOutcome(reply);
}

/**
 * Read the wallet's outcome.
 *
 * A `requireConsent` refusal is not a failure — it is the flow working. It
 * carries the digest the user must match, and it tells us the VTA has already
 * sent the effects to their approving device. Rendering it as an error would
 * strand the user at exactly the moment they were supposed to act.
 *
 * The wallet does the recognising (`@openvtc/pnm-core`'s `requestTask`), because
 * only it sits above the transport that would otherwise throw the refusal away.
 * We consume the outcome it hands us and do not attempt to re-derive it: the
 * previous version of this function read a `reason` member that does not exist on
 * the wire, which failed silently — the refusal simply looked like an ordinary
 * error, and the code panel below was never reached.
 */
function readOutcome(reply: Record<string, unknown>): RequestTaskOutcome {
  if (reply?.kind !== "consentRequired") {
    return { kind: "accepted", result: reply };
  }

  const payloadDigest = typeof reply.payloadDigest === "string" ? reply.payloadDigest : "";
  if (!payloadDigest) {
    // A refusal with nothing to match is not something we can put in front of a
    // human. Fail loudly rather than show a blank ceremony.
    throw new Error("Your agent asked for approval but sent no code to match.");
  }

  return {
    kind: "consentRequired",
    payloadDigest,
    approverSet: typeof reply.approverSet === "string" ? reply.approverSet : "",
    minApprovals: typeof reply.minApprovals === "number" ? reply.minApprovals : 1,
    // The class the VTA derived from the handler it is about to run. It is inside
    // the signed consent request, which is the only place it can be trusted from.
    sideEffects: sideEffectsOf(reply),
  };
}

/**
 * The task's side-effect class, read from the executor-**signed** consent request.
 *
 * Not from the refusal's top level, which carries no class — and not from a
 * registry, which is advisory and would make the "do I have to match a code?"
 * decision downgradeable by whoever publishes it.
 */
function sideEffectsOf(reply: Record<string, unknown>): string | undefined {
  const requests = Array.isArray(reply.consentRequests) ? reply.consentRequests : [];
  const first = requests[0] as { payload?: { sideEffects?: unknown } } | undefined;
  const level = first?.payload?.sideEffects;
  return typeof level === "string" ? level : undefined;
}
