/** VTI browser-extension wallet bridge.
 *
 * On web, the wallet extension injects `window.vtaWallet` into pages matching
 * its `host_permissions`. This module is the UI-side feature-detect + a thin
 * wrapper that asks the wallet to log into THIS did-hosting server.
 *
 * The wallet signs in with `auth/challenge/0.1` then `auth/authenticate/0.2`,
 * sent to `${baseUrl}/trust-tasks`, and returns a server-issued bearer token.
 * That token is fed into `AuthProvider.login(...)` identically to the passkey
 * path; both yield the same JWT shape. Like the passkey path, the login binds
 * this browser's session key, so later calls are signed without the wallet
 * (see `wallet-login.ts`).
 *
 * Native (iOS / Android) builds never see `window.vtaWallet`; the helper
 * degrades gracefully via `isWalletAvailable()`.
 */

import { Platform } from "react-native";

import { getApiBase } from "./api-base";
import { clearSessionKeypair } from "./session-key";
import { getServiceInfo } from "./trust-task";
import {
  authenticateIdTokenBindingSessionKey,
  loginBindingSessionKey,
  type VtaWalletLoginParams,
  type VtaWalletLoginResult,
} from "./wallet-login";

export type { VtaWalletLoginResult };

/* The subset of the wallet provider's interface this UI uses. Declaring it
 * inline keeps did-hosting-ui from depending on the extension package. The
 * full interface lives in `@openvtc/pnm-extension/provider.ts`. */
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
    entryId?: string;
    nonce?: string;
    target?: { kind: string; [k: string]: unknown };
    ttlSecondsHint?: number;
  }): Promise<ProxyLoginWireResult>;
  /** Raise an existing session to `aal2`. The wallet sends
   *  `auth/step-up/start/0.1` to `{baseUrl}/trust-tasks`, verifies the signed
   *  reply and the approve-request inside it (issuer `rpDid`, this session),
   *  asks the user, answers with a signed `approve-response/0.5`, and renews
   *  the session with `auth/refresh/0.1`. Resolves with the renewed tokens. */
  stepUpVta?(params: {
    baseUrl: string;
    rpDid: string;
    accessToken: string;
    refreshToken: string;
    sessionId: string;
  }): Promise<VtaWalletLoginResult>;
  /** Which persona this site knows the user as, resolving or binding one.
   *  Mints nothing and issues no session. Present from the wallet build that
   *  added first-use persona binding (OpenVTC/vta-browser-plugin#145). */
  walletProfile?(params: {
    target?: { kind: string; [k: string]: unknown };
  }): Promise<{ did: string; entryId: string; bound: boolean }>;
}
declare global {
  interface Window {
    vtaWallet?: VtaWalletProvider;
  }
}

/** True iff this is a web build AND the wallet extension has injected its
 *  provider into the page. False on iOS/Android or when the extension is
 *  missing — callers should hide the wallet button + show an install hint. *
 * @deprecated Contract C7: SIOPv2 / extension login is legacy. Use wallet
 * sign-in with a trigger link (`oob-sign-in.ts`); kept, behind "Using an
 * older wallet?", until a removal date is set.
 */
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
 *  the signed `server/info` Trust Task (`serviceDid`). That is the exact value the
 *  server compares the id_token `aud` against in `auth.rs`, so the wallet
 *  and the verifier can never disagree — and a single prebuilt UI bundle
 *  works against any deployment without baking a DID in at build time.
 *  `getServiceInfo()` caches per-tab, so this is one network round-trip.
 *
 *  `EXPO_PUBLIC_RP_DID` remains an explicit override for the unusual case
 *  where the wallet must target a DID other than this deployment's
 *  control-plane DID; leave it unset to track the control plane. */
export async function getRpDid(): Promise<string> {
  const override = process.env.EXPO_PUBLIC_RP_DID;
  if (override) return override;
  return (await getServiceInfo()).serviceDid;
}

export { getApiBase };

/** Sign in through the wallet, binding this browser's session key to the new
 *  session. Resolves to the result containing the server-issued access token
 *  (suitable for `AuthProvider.login`). Rejects if the wallet isn't
 *  available, the user denies the consent prompt, the control plane refuses
 *  the login, or the key was not bound. *
 * @deprecated Contract C7: SIOPv2 / extension login is legacy. Use wallet
 * sign-in with a trigger link (`oob-sign-in.ts`); kept, behind "Using an
 * older wallet?", until a removal date is set.
 */
export async function loginWithWallet(): Promise<VtaWalletLoginResult> {
  if (!isWalletAvailable()) {
    throw new Error(
      "VTA wallet extension is not installed (or this isn't running in a web browser).",
    );
  }
  return loginBindingSessionKey(window.vtaWallet!, {
    rpDid: await getRpDid(),
    baseUrl: getApiBase(),
  });
}

/** True iff the page-world wallet exposes the whole proxy-login surface this
 *  screen drives: `walletProfile` to resolve the identity, `proxyLogin` to mint
 *  as it, and `vaultList` for the pick-a-different-identity path. The demo's
 *  wallet-proxy buttons are hidden when this is false.
 *
 *  Presence detection, not version negotiation — the extension may simply not
 *  be installed. There is deliberately no separate probe per method: every
 *  build that has one has all three, so a second probe would only describe a
 *  wallet that does not exist. *
 * @deprecated Contract C7: SIOPv2 / extension login is legacy. Use wallet
 * sign-in with a trigger link (`oob-sign-in.ts`); kept, behind "Using an
 * older wallet?", until a removal date is set.
 */
export function isWalletProxyAvailable(): boolean {
  return (
    isWalletAvailable() &&
    typeof window.vtaWallet?.walletProfile === "function" &&
    typeof window.vtaWallet?.proxyLogin === "function" &&
    typeof window.vtaWallet?.vaultList === "function"
  );
}

/**
 * Ask the wallet which persona this RP knows the operator as, binding one if
 * this is a first sign-in.
 *
 * Returns a `ProxyVaultEntry` so it drops into `loginWithWalletProxy` and the
 * visualization below is unchanged — the demo's whole point is showing the
 * round-trip, and the round-trip did not move. Only the way the entry is found
 * did: `listProxyCandidates()` asks the wallet to enumerate *every* entry
 * pinned to this RP in order to find one, which discloses the operator's vault
 * to answer a question about a single entry, and on a fresh wallet returns
 * nothing at all.
 *
 * The persona DID must be known before `/auth/challenge`, which is bound to it
 * — so this cannot be folded into `proxyLogin` as one call.
 *
 * @deprecated Contract C7: SIOPv2 / extension login is legacy. Use wallet
 * sign-in with a trigger link (`oob-sign-in.ts`); kept, behind "Using an
 * older wallet?", until a removal date is set.
 */
export async function resolveProxyEntry(): Promise<{
  entry: ProxyVaultEntry;
  bound: boolean;
}> {
  if (!isWalletProxyAvailable()) {
    throw new Error(
      "VTI Wallet doesn't expose proxy-login APIs (extension may be out of date).",
    );
  }
  const rpDid = await getRpDid();
  const profile = await window.vtaWallet!.walletProfile!({
    target: { kind: "did", did: rpDid },
  });
  if (!profile.did || !profile.entryId) {
    throw new Error("Wallet returned no identity for this site.");
  }
  return {
    // Only the two fields the proxy round-trip reads are known here, and the
    // rest are not invented: this is the wallet's answer about one entry, not
    // a vault listing, and a fabricated label or context would be a claim
    // nothing checked.
    entry: {
      id: profile.entryId,
      label: profile.did,
      contextId: "",
      secretKind: "didSelfIssued",
      principalDid: profile.did,
      targets: [{ kind: "did", did: rpDid }],
    },
    bound: profile.bound,
  };
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
 *  to the RP's DID. Used by the login UI to populate the entry picker. *
 * @deprecated Contract C7: SIOPv2 / extension login is legacy. Use wallet
 * sign-in with a trigger link (`oob-sign-in.ts`); kept, behind "Using an
 * older wallet?", until a removal date is set.
 */
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
 *  walkthrough UI. *
 * @deprecated Contract C7: SIOPv2 / extension login is legacy. Use wallet
 * sign-in with a trigger link (`oob-sign-in.ts`); kept, behind "Using an
 * older wallet?", until a removal date is set.
 */
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
  // Drop any session key left from an earlier sign-in before anything can
  // fail: `trust-task.ts` signs with whatever key is held, and the control
  // plane refuses one this session never bound. Step 3 binds a fresh one.
  clearSessionKeypair();
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

  // ─── Step 3: post the id_token, wrapped as an `auth/authenticate/0.3`
  //            proxied authenticate, to /trust-tasks. The server verifies
  //            the outer document's proof (the fresh session key, as the
  //            delegate), then independently verifies the id_token itself as
  //            `delegationEvidence` — signature, nonce against this same
  //            challenge, aud, iat/exp — before honoring `principal`. Success
  //            issues access tokens for a session bound to that same fresh
  //            key, so the session's calls are signed without a wallet
  //            prompt each.
  const tAuth = performance.now();
  const { response: tokenResp, sent: authEnv } = await authenticateIdTokenBindingSessionKey(
    apiBase,
    {
      idToken: idTokenCompact,
      sessionId: chJson.sessionId,
      challenge: chJson.challenge,
      principalDid: entry.principalDid,
      rpDid,
    },
  );
  steps.push({
    label: "3. Server verifies + issues bearer",
    description: `Server verifies the outer document's proof from the session key (the delegate), independently verifies the id_token as delegationEvidence for the principal DID, checks its nonce matches the challenge from step 1, and issues a bearer access token bound to the principal DID — and to the session key this browser generated, which signs the session's calls from here on.`,
    durationMs: Math.round(performance.now() - tAuth),
    detail: {
      url: `${apiBase}/trust-tasks`,
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

/** Park / resume an agent name. Same `vta/webvh/...` dispatch discipline as
 *  {@link WEBVH_DIDS_UPDATE_1_0}. */
export const WEBVH_AGENT_NAME_DISABLE_1_0 =
  "https://trusttasks.org/spec/vta/webvh/agent-name/disable/1.0";
export const WEBVH_AGENT_NAME_ENABLE_1_0 =
  "https://trusttasks.org/spec/vta/webvh/agent-name/enable/1.0";

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

// The operator's comparison code lives in its own import-free module so
// the test runner can reach it; this file imports `react-native`, which
// vitest cannot parse. Re-exported here so callers keep one import site.
export { DIGEST_PREFIX_LEN, digestPrefix } from "./digest-code";

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
 * Ask the user's VTA to park (`enable: false`) or resume (`enable: true`) an
 * agent name on a hosted DID.
 *
 * Unlike {@link requestDidUpdate}, we don't send a document — the VTA reads the
 * DID's current document itself, edits `alsoKnownAs`, signs the new version, and
 * calls the host's agent-name endpoint. The task is classified `destructive`,
 * so the same cross-device approval ceremony applies (see {@link readOutcome}).
 */
export async function requestAgentNameTask(args: {
  did: string;
  name: string;
  enable: boolean;
}): Promise<RequestTaskOutcome> {
  const wallet = window.vtaWallet;
  if (!wallet?.requestTask) {
    throw new Error("This wallet does not support delegated task execution.");
  }
  const reply = (await wallet.requestTask({
    type: args.enable ? WEBVH_AGENT_NAME_ENABLE_1_0 : WEBVH_AGENT_NAME_DISABLE_1_0,
    payload: { did: args.did, name: args.name },
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
